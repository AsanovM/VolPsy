# -*- coding: utf-8 -*-
import os
import sys
import json
import inspect
import threading
import time

from java.io import File, FileInputStream, BufferedReader, InputStreamReader, FileOutputStream, OutputStreamWriter, BufferedWriter, IOException
from java.lang import ProcessBuilder
from java.util import ArrayList
from java.util.logging import Level
from java.util.concurrent import Executors, TimeUnit, TimeoutException, Callable

from javax.swing import (JPanel, JCheckBox, JLabel, JTextField, JButton, JScrollPane,
                         BoxLayout, JFileChooser, JOptionPane)
from javax.swing.border import TitledBorder, EmptyBorder
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener

from org.sleuthkit.autopsy.ingest import (IngestModuleFactoryAdapter, DataSourceIngestModule,
                                          IngestModuleIngestJobSettings, IngestModuleIngestJobSettingsPanel,
                                          IngestServices, IngestMessage, IngestModule)
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger

MODULE_NAME = "Volatility 3 Ingest Module"
MODULE_VERSION = "1.0"
OS_WINDOWS = "windows"
OS_LINUX = "linux"
IngestModuleException = IngestModule.IngestModuleException
OS_MAC = "mac"
CASE_MODULE_OUTPUT_TOKEN = "CASE_MODULE_OUTPUT"
SETTINGS_LOGGER = Logger.getLogger("Vol3JobSettings")

OS_DETECTION_SEQUENCE = [
    (OS_WINDOWS, "windows.info", "json"),
    (OS_LINUX, "linux.banners", "json"),
    (OS_MAC, "mac.nt_tasks", "json")
]


def _module_directory():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        frame = inspect.currentframe()
        return os.path.dirname(os.path.abspath(inspect.getfile(frame)))


class Vol3Config(object):
    def __init__(self, config_path, logger):
        self.logger = logger
        self.config_path = config_path
        self.sections = {}

    def load(self):
        self.sections = {}
        config_file = File(self.config_path)
        if not config_file.exists():
            self.logger.log(Level.WARNING, "Configuration file not found: " + config_file.getAbsolutePath())
            return
        stream = None
        reader = None
        try:
            if self.logger is not None:
                try:
                    cmd_desc = []
                    for i in range(args.size()):
                        cmd_desc.append(str(args.get(i)))
                    self.logger.log(Level.INFO, "Executing command: " + " ".join(cmd_desc))
                except Exception:
                    pass
            stream = FileInputStream(config_file)
            reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
            current = None
            while True:
                line = reader.readLine()
                if line is None:
                    break
                text = line.strip()
                if len(text) == 0 or text.startswith("#") or text.startswith(";"):
                    continue
                if text.startswith("[") and text.endswith("]"):
                    current = text[1:-1].strip().lower()
                    if current not in self.sections:
                        self.sections[current] = {}
                else:
                    if current is None:
                        continue
                    parts = text.split("=", 1)
                    if len(parts) == 2:
                        key = parts[0].strip().lower()
                        value = parts[1].strip()
                        self.sections[current][key] = value
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Failed to load config.ini: " + str(ex))
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass

    def get(self, section, key, default_value):
        if section is None or key is None:
            return default_value
        section_key = section.lower()
        option_key = key.lower()
        if section_key in self.sections and option_key in self.sections[section_key]:
            return self.sections[section_key][option_key]
        return default_value

    def get_list(self, section, key):
        value = self.get(section, key, "")
        if value is None or len(value) == 0:
            return []
        parts = value.split(",")
        items = []
        for part in parts:
            entry = part.strip()
            if len(entry) > 0:
                items.append(entry)
        return items

    def get_int(self, section, key, default_value):
        value = self.get(section, key, None)
        if value is None or len(value) == 0:
            return default_value
        try:
            return int(value)
        except Exception:
            self.logger.log(Level.WARNING, "Invalid integer for [{0}] {1}: {2}".format(section, key, value))
            return default_value


class PluginExecutionResult(object):
    def __init__(self):
        self.exit_code = -1
        self.timed_out = False
        self.cancelled = False
        self.error = None
        self.stdout_truncated = False
        self.stderr_truncated = False
        self.stdout_path = None
        self.stderr_path = None


class _ProcessWaitCallable(Callable):
    def __init__(self, process):
        self.process = process

    def call(self):
        return self.process.waitFor()


class _StreamCollector(object):
    def __init__(self, input_stream, target_path, max_bytes, append_mode):
        self.input_stream = input_stream
        self.target_path = target_path
        self.max_bytes = max_bytes
        self.append_mode = append_mode
        self.truncated = False
        self.error = None

    def run(self):
        writer = None
        reader = None
        try:
            if self.target_path is not None:
                file_obj = File(self.target_path)
                parent = file_obj.getParentFile()
                if parent is not None and not parent.exists():
                    parent.mkdirs()
                writer = BufferedWriter(OutputStreamWriter(FileOutputStream(file_obj, self.append_mode), "UTF-8"))
            reader = BufferedReader(InputStreamReader(self.input_stream, "UTF-8"))
            total = 0
            while True:
                line = reader.readLine()
                if line is None:
                    break
                encoded = (line + "\n").encode("UTF-8")
                total += len(encoded)
                if self.max_bytes > 0 and total > self.max_bytes:
                    self.truncated = True
                    if writer is not None:
                        writer.write(u"[vol3] Output truncated (exceeded configured limit)\n")
                        writer.flush()
                    while reader.readLine() is not None:
                        pass
                    break
                if writer is not None:
                    writer.write(line)
                    writer.write("\n")
            if writer is not None:
                writer.flush()
        except Exception as ex:
            self.error = str(ex)
        finally:
            try:
                self.input_stream.close()
            except Exception:
                pass
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass


class Vol3Runner(object):
    def __init__(self, logger, python_exe, volatility_exe, timeout_sec, max_stdout_bytes):
        self.logger = logger
        self.python_exe = python_exe
        self.volatility_exe = volatility_exe
        self.timeout_sec = timeout_sec
        self.max_stdout_bytes = max_stdout_bytes

    def run_plugin(self, dump_path, plugin_name, renderer, stdout_path, stderr_path, timeout_sec, cancel_check):
        args = ArrayList()
        args.add(self.python_exe)
        args.add(self.volatility_exe)
        args.add("-f")
        args.add(str(dump_path))
        args.add(plugin_name)
        args.add("--renderer")
        args.add(renderer)
        return self._execute(args, stdout_path, stderr_path, timeout_sec, cancel_check)

    def run_detection(self, dump_path, plugin_name, renderer, timeout_sec, cancel_check):
        args = ArrayList()
        args.add(self.python_exe)
        args.add(self.volatility_exe)
        args.add("-f")
        args.add(str(dump_path))
        args.add(plugin_name)
        args.add("--renderer")
        args.add(renderer)
        return self._execute(args, None, None, timeout_sec, cancel_check)

    def verify_binaries(self):
        args = ArrayList()
        args.add(self.python_exe)
        args.add(self.volatility_exe)
        args.add("--help")
        result = self._execute(args, None, None, 30, None)
        if result.error is not None:
            raise Exception("Volatility --help failed: " + result.error)
        if result.timed_out:
            raise Exception("Volatility --help timed out")
        if result.exit_code != 0:
            raise Exception("Volatility --help returned exit code " + str(result.exit_code))

    def query_available_plugins(self, timeout_sec):
        args = ArrayList()
        args.add(self.python_exe)
        args.add(self.volatility_exe)
        args.add("--info")
        stdout_tmp = File.createTempFile("vol3_plugins", ".txt")
        stderr_tmp = File.createTempFile("vol3_plugins_err", ".txt")
        stdout_tmp.deleteOnExit()
        stderr_tmp.deleteOnExit()
        try:
            result = self._execute(args, stdout_tmp.getAbsolutePath(), stderr_tmp.getAbsolutePath(), timeout_sec, None)
            output = self._read_text_file(stdout_tmp)
            error_output = self._read_text_file(stderr_tmp)
            return (result, output, error_output)
        finally:
            stdout_tmp.delete()
            stderr_tmp.delete()

    def _read_text_file(self, file_obj):
        target = file_obj
        if target is None:
            return ""
        if not isinstance(target, File):
            target = File(str(target))
        if not target.exists():
            return ""
        reader = None
        try:
            reader = BufferedReader(InputStreamReader(FileInputStream(target), "UTF-8"))
            lines = []
            while True:
                line = reader.readLine()
                if line is None:
                    break
                lines.append(line)
            if len(lines) == 0:
                return ""
            return "\n".join(lines)
        except Exception:
            return ""
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass

    def _execute(self, args, stdout_path, stderr_path, timeout_sec, cancel_check):
        result = PluginExecutionResult()
        result.stdout_path = stdout_path
        result.stderr_path = stderr_path
        if timeout_sec is None or timeout_sec <= 0:
            timeout_sec = self.timeout_sec
        if self.logger is not None:
            try:
                cmd_desc = []
                for i in range(args.size()):
                    cmd_desc.append(str(args.get(i)))
                self.logger.log(Level.INFO, "Executing command: " + " ".join(cmd_desc))
            except Exception:
                pass
        process = None
        executor = None
        future = None
        stdout_collector = None
        stderr_collector = None
        stdout_thread = None
        stderr_thread = None
        try:
            builder = ProcessBuilder(args)
            process = builder.start()
            stdout_collector = _StreamCollector(process.getInputStream(), stdout_path, self.max_stdout_bytes, False)
            stderr_collector = _StreamCollector(process.getErrorStream(), stderr_path, self.max_stdout_bytes, False)
            stdout_thread = threading.Thread(target=stdout_collector.run, name="vol3-stdout")
            stderr_thread = threading.Thread(target=stderr_collector.run, name="vol3-stderr")
            stdout_thread.setDaemon(True)
            stderr_thread.setDaemon(True)
            stdout_thread.start()
            stderr_thread.start()

            executor = Executors.newSingleThreadExecutor()
            future = executor.submit(_ProcessWaitCallable(process))
            deadline = time.time() + timeout_sec
            exit_code = None
            while True:
                if cancel_check is not None and cancel_check():
                    result.cancelled = True
                    process.destroyForcibly()
                    break
                try:
                    exit_code = future.get(1, TimeUnit.SECONDS)
                    break
                except TimeoutException:
                    if timeout_sec > 0 and time.time() > deadline:
                        result.timed_out = True
                        process.destroyForcibly()
                        break
                except Exception as ex:
                    result.error = str(ex)
                    process.destroyForcibly()
                    break
            if exit_code is not None:
                result.exit_code = exit_code
            if future is not None:
                future.cancel(True)
        except IOException as ioex:
            result.error = str(ioex)
            if process is not None:
                process.destroyForcibly()
        finally:
            if executor is not None:
                executor.shutdownNow()
            if process is not None:
                try:
                    process.waitFor()
                except Exception:
                    pass
            if stdout_thread is not None:
                stdout_thread.join()
            if stderr_thread is not None:
                stderr_thread.join()
            if stdout_collector is not None:
                result.stdout_truncated = stdout_collector.truncated
                if stdout_collector.error is not None:
                    result.error = stdout_collector.error
            if stderr_collector is not None:
                result.stderr_truncated = stderr_collector.truncated
                if stderr_collector.error is not None:
                    result.error = stderr_collector.error
        if self.logger is not None:
            try:
                self.logger.log(Level.INFO, "Command exit code: {0}".format(result.exit_code))
            except Exception:
                pass
        return result

class Vol3JobSettings(IngestModuleIngestJobSettings):
    VERSION_NUMBER = 1
    serialVersionUID = 1

    def __init__(self):
        self._selected_plugins = {
            OS_WINDOWS: [],
            OS_LINUX: [],
            OS_MAC: []
        }
        self._python_exe = ""
        self._vol_exe = ""
        self._reports_root = ""

    def getVersionNumber(self):
        return Vol3JobSettings.VERSION_NUMBER

    def setSelectedPlugins(self, os_key, plugins):
        if os_key in self._selected_plugins:
            self._selected_plugins[os_key] = list(plugins)

    def getSelectedPlugins(self, os_key):
        if os_key in self._selected_plugins:
            return list(self._selected_plugins[os_key])
        return []

    def getAllSelectedPlugins(self):
        result = []
        for os_key in self._selected_plugins:
            for item in self._selected_plugins[os_key]:
                if item not in result:
                    result.append(item)
        return result

    def setPythonExe(self, path):
        if path is None:
            self._python_exe = ""
        else:
            self._python_exe = path

    def getPythonExe(self):
        return self._python_exe

    def setVolatilityExe(self, path):
        if path is None:
            self._vol_exe = ""
        else:
            self._vol_exe = path

    def getVolatilityExe(self):
        return self._vol_exe

    def setReportsRoot(self, path):
        if path is None:
            self._reports_root = ""
        else:
            self._reports_root = path

    def getReportsRoot(self):
        return self._reports_root

    def serialize(self):
        payload = {
            "python_exe": self._python_exe,
            "vol_exe": self._vol_exe,
            "reports_root": self._reports_root,
            "selected_plugins": self._selected_plugins
        }
        try:
            return json.dumps(payload)
        except Exception as ex:
            SETTINGS_LOGGER.log(Level.WARNING, "Failed to serialize job settings: " + str(ex))
            return "{}"

    def deserialize(self, serialized):
        if serialized is None or len(serialized) == 0:
            return
        try:
            data = json.loads(serialized)
        except Exception as ex:
            SETTINGS_LOGGER.log(Level.WARNING, "Failed to deserialize job settings: " + str(ex))
            return
        try:
            self._python_exe = data.get("python_exe", "")
            self._vol_exe = data.get("vol_exe", "")
            self._reports_root = data.get("reports_root", "")
            selected = data.get("selected_plugins", {})
            if isinstance(selected, dict):
                for os_key in (OS_WINDOWS, OS_LINUX, OS_MAC):
                    plugins = selected.get(os_key, [])
                    if isinstance(plugins, list):
                        cleaned = []
                        for item in plugins:
                            if item is not None:
                                cleaned.append(str(item))
                        self._selected_plugins[os_key] = cleaned
        except Exception as ex:
            SETTINGS_LOGGER.log(Level.WARNING, "Error applying deserialized settings: " + str(ex))


class Vol3PluginPlan(object):
    def __init__(self, config, settings):
        self.config = config
        self.settings = settings

    def _default_plugins(self, os_key):
        if os_key == OS_WINDOWS:
            return self.config.get_list("plugins.win", "whitelist")
        if os_key == OS_LINUX:
            return self.config.get_list("plugins.lin", "whitelist")
        if os_key == OS_MAC:
            return self.config.get_list("plugins.mac", "whitelist")
        return []

    def compute_plugins(self, detected_os):
        if detected_os in (OS_WINDOWS, OS_LINUX, OS_MAC):
            selected = self.settings.getSelectedPlugins(detected_os)
            if selected is None or len(selected) == 0:
                selected = self._default_plugins(detected_os)
            return self._dedupe(selected)
        combined = []
        for os_key in (OS_WINDOWS, OS_LINUX, OS_MAC):
            selected = self.settings.getSelectedPlugins(os_key)
            if selected is None or len(selected) == 0:
                selected = self._default_plugins(os_key)
            for item in selected:
                if item not in combined:
                    combined.append(item)
        return combined

    def _dedupe(self, plugins):
        result = []
        for item in plugins:
            if item not in result:
                result.append(item)
        return result

class Vol3SettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings, config, logger):
        IngestModuleIngestJobSettingsPanel.__init__(self)
        self.logger = logger
        self.config = config
        self.original_settings = settings
        self.available_plugins = {
            OS_WINDOWS: self.config.get_list("plugins.win", "whitelist"),
            OS_LINUX: self.config.get_list("plugins.lin", "whitelist"),
            OS_MAC: self.config.get_list("plugins.mac", "whitelist")
        }
        self.plugin_checkboxes = {
            OS_WINDOWS: [],
            OS_LINUX: [],
            OS_MAC: []
        }
        self.plugin_panels = {}
        self.status_label = JLabel(" ")
        self.default_timeout = self.config.get_int("limits", "timeout_sec_per_plugin", 600)
        max_mb = self.config.get_int("limits", "max_stdout_mb", 64)
        if max_mb <= 0:
            max_mb = 64
        self.default_max_stdout = max_mb * 1024 * 1024
        self._build_ui()
        self._load_settings(settings)

    def _build_ui(self):
        self.setLayout(BorderLayout(10, 10))
        self.setBorder(EmptyBorder(10, 10, 10, 10))

        paths_panel = JPanel(GridBagLayout())
        self.python_field = JTextField(30)
        self.vol_field = JTextField(30)
        self.reports_field = JTextField(30)

        self._add_path_row(paths_panel, 0, "Python executable:", self.python_field, False)
        self._add_path_row(paths_panel, 1, "Volatility script:", self.vol_field, False)
        self._add_path_row(paths_panel, 2, "Reports root:", self.reports_field, True)

        self.add(paths_panel, BorderLayout.NORTH)

        plugins_container = JPanel()
        plugins_container.setLayout(BoxLayout(plugins_container, BoxLayout.Y_AXIS))
        for os_key in (OS_WINDOWS, OS_LINUX, OS_MAC):
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
            panel.setBorder(TitledBorder(os_key.capitalize() + " plugins"))
            plugins_container.add(panel)
            self.plugin_panels[os_key] = panel
        scroll = JScrollPane(plugins_container)
        scroll.setBorder(TitledBorder("Volatility 3 plugins"))
        self.add(scroll, BorderLayout.CENTER)

        bottom = JPanel(BorderLayout(5, 5))
        refresh = JButton("Refresh plugins")
        refresh.addActionListener(self._create_refresh_action())
        bottom.add(refresh, BorderLayout.WEST)
        bottom.add(self.status_label, BorderLayout.CENTER)
        self.add(bottom, BorderLayout.SOUTH)

    def _add_path_row(self, panel, index, label_text, text_field, directories_only):
        label_constraints = GridBagConstraints()
        label_constraints.gridx = 0
        label_constraints.gridy = index
        label_constraints.anchor = GridBagConstraints.WEST
        label_constraints.insets = Insets(4, 4, 4, 4)
        panel.add(JLabel(label_text), label_constraints)

        field_constraints = GridBagConstraints()
        field_constraints.gridx = 1
        field_constraints.gridy = index
        field_constraints.weightx = 1.0
        field_constraints.fill = GridBagConstraints.HORIZONTAL
        field_constraints.insets = Insets(4, 4, 4, 4)
        panel.add(text_field, field_constraints)

        button_constraints = GridBagConstraints()
        button_constraints.gridx = 2
        button_constraints.gridy = index
        button_constraints.insets = Insets(4, 4, 4, 4)
        browse = JButton("Browse")
        browse.addActionListener(self._create_file_action(text_field, directories_only))
        panel.add(browse, button_constraints)

    def _create_file_action(self, text_field, directories_only):
        panel = self

        class _Chooser(ActionListener):
            def actionPerformed(inner_self, event):
                chooser = JFileChooser()
                if directories_only:
                    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
                else:
                    chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
                existing = text_field.getText().strip()
                if len(existing) > 0:
                    chooser.setSelectedFile(File(existing))
                result = chooser.showOpenDialog(panel)
                if result == JFileChooser.APPROVE_OPTION:
                    selected = chooser.getSelectedFile()
                    if selected is not None:
                        text_field.setText(selected.getAbsolutePath())

        return _Chooser()

    def _create_refresh_action(self):
        panel = self

        class _Refresh(ActionListener):
            def actionPerformed(inner_self, event):
                panel._refresh_plugins()

        return _Refresh()

    def _load_settings(self, settings):
        python_default = self.config.get("runtime", "python_exe", "")
        vol_default = self.config.get("runtime", "vol_exe", "")
        reports_default = self.config.get("output", "reports_root", CASE_MODULE_OUTPUT_TOKEN)

        python_value = settings.getPythonExe()
        if python_value is None or len(python_value) == 0:
            python_value = python_default
        vol_value = settings.getVolatilityExe()
        if vol_value is None or len(vol_value) == 0:
            vol_value = vol_default
        reports_value = settings.getReportsRoot()
        if reports_value is None or len(reports_value) == 0:
            reports_value = reports_default

        self.python_field.setText(python_value)
        self.vol_field.setText(vol_value)
        self.reports_field.setText(reports_value)

        selection_map = {}
        for os_key in (OS_WINDOWS, OS_LINUX, OS_MAC):
            selected = settings.getSelectedPlugins(os_key)
            if selected is None or len(selected) == 0:
                selected = self.available_plugins.get(os_key, [])
            selection_map[os_key] = list(selected)
        self._rebuild_checkboxes(selection_map)

    def _rebuild_checkboxes(self, selected_map):
        for os_key in (OS_WINDOWS, OS_LINUX, OS_MAC):
            panel = self.plugin_panels[os_key]
            panel.removeAll()
            self.plugin_checkboxes[os_key] = []
            plugins = self.available_plugins.get(os_key, [])
            for plugin in plugins:
                checkbox = JCheckBox(plugin)
                if os_key in selected_map and plugin in selected_map[os_key]:
                    checkbox.setSelected(True)
                panel.add(checkbox)
                self.plugin_checkboxes[os_key].append(checkbox)
            panel.revalidate()
            panel.repaint()

    def _collect_selections(self):
        result = {}
        for os_key in self.plugin_checkboxes:
            selected = []
            checkboxes = self.plugin_checkboxes[os_key]
            for checkbox in checkboxes:
                if checkbox.isSelected():
                    selected.append(checkbox.getText())
            result[os_key] = selected
        return result

    def _parse_plugins_from_text(self, text):
        if text is None:
            return []
        names = []
        lines = text.splitlines()
        for line in lines:
            stripped = line.strip()
            if len(stripped) == 0:
                continue
            if stripped.startswith("Volatility"):
                continue
            token = stripped.split()[0]
            if token.endswith(":"):
                token = token[:-1]
            if "." in token and token not in names:
                names.append(token)
        return names

    def _refresh_plugins(self):
        python_path = self.python_field.getText().strip()
        vol_path = self.vol_field.getText().strip()
        if len(python_path) == 0 or len(vol_path) == 0:
            self._set_status("Set python and Volatility paths before refresh", Level.WARNING)
            return
        runner = Vol3Runner(self.logger, python_path, vol_path, self.default_timeout, self.default_max_stdout)
        try:
            result, output, error_output = runner.query_available_plugins(min(120, self.default_timeout))
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to query plugins: " + str(ex))
            self._set_status("Failed to refresh plugins: " + str(ex), Level.WARNING)
            return
        if result.timed_out:
            self._set_status("Plugin query timed out", Level.WARNING)
            return
        plugins = self._parse_plugins_from_text(output)
        if len(plugins) == 0:
            self._set_status("No plugin names found", Level.WARNING)
            return
        new_map = {
            OS_WINDOWS: [],
            OS_LINUX: [],
            OS_MAC: []
        }
        for name in plugins:
            if name.startswith("windows."):
                new_map[OS_WINDOWS].append(name)
            elif name.startswith("linux."):
                new_map[OS_LINUX].append(name)
            elif name.startswith("mac."):
                new_map[OS_MAC].append(name)
        for os_key in new_map:
            if len(new_map[os_key]) == 0:
                new_map[os_key] = self.available_plugins.get(os_key, [])
        selections = self._collect_selections()
        self.available_plugins = new_map
        self._rebuild_checkboxes(selections)
        self._set_status("Plugin list refreshed", Level.INFO)

    def _set_status(self, message, level):
        if message is None:
            message = ""
        self.status_label.setText(message)
        if level == Level.WARNING:
            self.logger.log(Level.WARNING, message)
        elif level == Level.SEVERE:
            self.logger.log(Level.SEVERE, message)
        else:
            self.logger.log(Level.INFO, message)

    def getSettings(self):
        settings = Vol3JobSettings()
        settings.setPythonExe(self.python_field.getText().strip())
        settings.setVolatilityExe(self.vol_field.getText().strip())
        settings.setReportsRoot(self.reports_field.getText().strip())
        for os_key in self.plugin_checkboxes:
            selected = []
            for checkbox in self.plugin_checkboxes[os_key]:
                if checkbox.isSelected():
                    selected.append(checkbox.getText())
            settings.setSelectedPlugins(os_key, selected)
        self._validate_paths(settings)
        return settings

    def _validate_paths(self, settings):
        warnings = []
        python_path = settings.getPythonExe()
        if python_path is None or len(python_path) == 0:
            warnings.append("Python executable path is empty.")
        else:
            if not File(python_path).exists():
                warnings.append("Python executable path does not exist: " + python_path)
        vol_path = settings.getVolatilityExe()
        if vol_path is None or len(vol_path) == 0:
            warnings.append("Volatility script path is empty.")
        else:
            if not File(vol_path).exists():
                warnings.append("Volatility script path does not exist: " + vol_path)
        if len(warnings) > 0:
            message = "\n".join(warnings)
            JOptionPane.showMessageDialog(self, message, "Volatility 3 settings", JOptionPane.WARNING_MESSAGE)
            self.logger.log(Level.WARNING, message)

class Vol3DataSourceIngestModule(DataSourceIngestModule):
    def __init__(self, settings):
        self.settings = settings
        self.logger = Logger.getLogger("Vol3DataSourceIngestModule")
        self.context = None
        self.config = None
        self.runner = None
        self.plugin_plan = None
        self.timeout_sec = 600
        self.max_stdout_bytes = 64 * 1024 * 1024
        self.report_root_dir = None
        self.json_dir = None
        self.txt_dir = None
        self.logs_dir = None
        self.success_count = 0
        self.failure_count = 0
        self.timeout_count = 0
        self.last_detected_os = None
        self.python_exe = ""
        self.vol_exe = ""
        self.reports_root_setting = ""

    def startUp(self, context):
        self.context = context
        module_dir = _module_directory()
        config_path = os.path.join(module_dir, "resources", "config.ini")
        self.config = Vol3Config(config_path, self.logger)
        self.config.load()

        python_path = self.settings.getPythonExe()
        if python_path is None or len(python_path) == 0:
            python_path = self.config.get("runtime", "python_exe", "")
        vol_path = self.settings.getVolatilityExe()
        if vol_path is None or len(vol_path) == 0:
            vol_path = self.config.get("runtime", "vol_exe", "")
        if python_path is None or len(python_path) == 0:
            raise IngestModuleException("Python executable path is not configured")
        if vol_path is None or len(vol_path) == 0:
            raise IngestModuleException("Volatility script path is not configured")
        self.python_exe = python_path
        self.vol_exe = vol_path

        reports_root = self.settings.getReportsRoot()
        if reports_root is None or len(reports_root) == 0:
            reports_root = self.config.get("output", "reports_root", CASE_MODULE_OUTPUT_TOKEN)
        if reports_root is None or len(reports_root) == 0:
            reports_root = CASE_MODULE_OUTPUT_TOKEN
        self.reports_root_setting = reports_root

        self.timeout_sec = self.config.get_int("limits", "timeout_sec_per_plugin", 600)
        if self.timeout_sec <= 0:
            self.timeout_sec = 600
        max_stdout_mb = self.config.get_int("limits", "max_stdout_mb", 64)
        if max_stdout_mb <= 0:
            max_stdout_mb = 64
        self.max_stdout_bytes = max_stdout_mb * 1024 * 1024

        self.runner = Vol3Runner(self.logger, self.python_exe, self.vol_exe, self.timeout_sec, self.max_stdout_bytes)
        try:
            self.runner.verify_binaries()
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Volatility verification failed: " + str(ex))
            raise IngestModuleException("Unable to execute Volatility 3 (--help failed): " + str(ex))

        self.plugin_plan = Vol3PluginPlan(self.config, self.settings)

    def process(self, dataSource, progressBar):
        dump_path = dataSource.getLocalAbsPath()
        if dump_path is None:
            self.logger.log(Level.SEVERE, "Data source does not have a local path")
            return DataSourceIngestModule.ProcessResult.ERROR

        ingest_services = IngestServices.getInstance()
        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                                                                "Volatility 3 run started for " + dataSource.getName()))

        self.report_root_dir = self._prepare_output_root()
        if self.report_root_dir is None:
            self.logger.log(Level.SEVERE, "Failed to prepare report output directory")
            return DataSourceIngestModule.ProcessResult.ERROR

        self.json_dir = File(self.report_root_dir, "json")
        self.txt_dir = File(self.report_root_dir, "txt")
        self.logs_dir = File(self.report_root_dir, "logs")
        self.json_dir.mkdirs()
        self.txt_dir.mkdirs()
        self.logs_dir.mkdirs()

        detected_os = self._detect_operating_system(dump_path)
        self.last_detected_os = detected_os
        if detected_os is not None:
            self.logger.log(Level.INFO, "Detected operating system: " + detected_os)
        else:
            self.logger.log(Level.INFO, "Operating system detection failed; using selected plugins")

        plugins = self.plugin_plan.compute_plugins(detected_os)
        if plugins is None or len(plugins) == 0:
            self.logger.log(Level.WARNING, "No plugins selected for execution")
            return DataSourceIngestModule.ProcessResult.OK

        total_steps = len(plugins) * 2
        if total_steps > 0:
            progressBar.switchToDeterminate(total_steps)
        else:
            progressBar.switchToIndeterminate()
        current_step = 0
        progressBar.progress("Initializing Volatility 3")
        progressBar.progress(current_step)
        self.success_count = 0
        self.failure_count = 0
        self.timeout_count = 0

        for plugin_name in plugins:
            if self._is_cancelled():
                self.logger.log(Level.INFO, "Ingest job cancelled during plugin execution")
                return DataSourceIngestModule.ProcessResult.OK
            safe_name = self._sanitize_plugin_name(plugin_name)
            json_path = File(self.json_dir, safe_name + ".jsonl").getAbsolutePath()
            txt_path = File(self.txt_dir, safe_name + ".txt").getAbsolutePath()
            stderr_final = File(self.logs_dir, safe_name + ".stderr.txt").getAbsolutePath()
            stderr_json_tmp = File(self.logs_dir, safe_name + ".stderr.json.tmp").getAbsolutePath()
            stderr_txt_tmp = File(self.logs_dir, safe_name + ".stderr.text.tmp").getAbsolutePath()
            timeout_note = File(self.logs_dir, safe_name + ".timeout.txt").getAbsolutePath()
            self._reset_file(json_path)
            self._reset_file(txt_path)
            self._reset_file(stderr_final)
            self._reset_file(stderr_json_tmp)
            self._reset_file(stderr_txt_tmp)
            self._reset_file(timeout_note)

            self.logger.log(Level.INFO, "Preparing plugin {0}".format(plugin_name))
            progressBar.progress("Preparing " + plugin_name)
            plugin_success = True
            plugin_timeout = False

            self.logger.log(Level.INFO, "Running plugin {0} (jsonl)".format(plugin_name))
            progressBar.progress("Running " + plugin_name + " (jsonl)")
            json_result = self.runner.run_plugin(dump_path, plugin_name, "jsonl", json_path, stderr_json_tmp, self.timeout_sec, self._is_cancelled)
            self._append_log(stderr_json_tmp, stderr_final, "[JSONL] " + plugin_name)
            current_step += 1
            progressBar.progress(current_step)
            progressBar.progress("Completed " + plugin_name + " (jsonl)")
            if json_result.cancelled:
                self.logger.log(Level.INFO, "Processing cancelled during plugin " + plugin_name)
                return DataSourceIngestModule.ProcessResult.OK
            if json_result.timed_out:
                plugin_timeout = True
                plugin_success = False
                self._write_timeout(timeout_note, plugin_name, "jsonl")
            if json_result.exit_code != 0:
                plugin_success = False
                self._ensure_file_has_message(json_path, "no results")
            if json_result.error is not None:
                plugin_success = False
                self.logger.log(Level.WARNING, "Error during plugin {0} (jsonl): {1}".format(plugin_name, json_result.error))

            self.logger.log(Level.INFO, "Running plugin {0} (text)".format(plugin_name))
            progressBar.progress("Running " + plugin_name + " (text)")
            txt_result = self.runner.run_plugin(dump_path, plugin_name, "text", txt_path, stderr_txt_tmp, self.timeout_sec, self._is_cancelled)
            self._append_log(stderr_txt_tmp, stderr_final, "[TEXT] " + plugin_name)
            current_step += 1
            progressBar.progress(current_step)
            progressBar.progress("Completed " + plugin_name + " (text)")
            if txt_result.cancelled:
                self.logger.log(Level.INFO, "Processing cancelled during plugin " + plugin_name)
                return DataSourceIngestModule.ProcessResult.OK
            if txt_result.timed_out:
                plugin_timeout = True
                plugin_success = False
                self._write_timeout(timeout_note, plugin_name, "text")
            if txt_result.exit_code != 0:
                plugin_success = False
                self._ensure_file_has_message(txt_path, "no results")
            if txt_result.error is not None:
                plugin_success = False
                self.logger.log(Level.WARNING, "Error during plugin {0} (text): {1}".format(plugin_name, txt_result.error))

            progressBar.progress("Finished " + plugin_name)
            if plugin_timeout:
                self.timeout_count += 1
            if plugin_success:
                self.success_count += 1
            else:
                self.failure_count += 1
        summary = "Volatility 3 finished for {0}. Success: {1}, Failed: {2}, Timed out: {3}. Output: {4}".format(
            dataSource.getName(), self.success_count, self.failure_count, self.timeout_count,
            self.report_root_dir.getAbsolutePath())
        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, MODULE_NAME, summary))
        self.logger.log(Level.INFO, summary)
        return DataSourceIngestModule.ProcessResult.OK

    def postProcess(self, progressBar):
        if self.report_root_dir is not None and self.report_root_dir.exists():
            Case.getCurrentCase().addReport(self.report_root_dir.getAbsolutePath(), MODULE_NAME, "Volatility 3 Report")

    def shutDown(self):
        self.logger.log(Level.INFO, "Volatility 3 ingest module shutdown")

    def _is_cancelled(self):
        if self.context is None:
            return False
        try:
            return self.context.isJobCancelled()
        except Exception:
            return False

    def _prepare_output_root(self):
        reports_root = self.reports_root_setting
        if reports_root is None or len(reports_root.strip()) == 0 or reports_root.strip().upper() == CASE_MODULE_OUTPUT_TOKEN:
            case_directory = Case.getCurrentCase().getCaseDirectory()
            base = File(case_directory, "ModuleOutput")
            if not base.exists():
                base.mkdirs()
            target = File(base, "Volatility3")
            target.mkdirs()
            return target
        base = File(reports_root)
        if not base.exists():
            base.mkdirs()
        target = File(base, "Volatility3")
        target.mkdirs()
        return target

    def _detect_operating_system(self, dump_path):
        for entry in OS_DETECTION_SEQUENCE:
            os_key, plugin_name, renderer = entry
            result = self.runner.run_detection(dump_path, plugin_name, renderer, min(120, self.timeout_sec), self._is_cancelled)
            if result.cancelled:
                return None
            if result.timed_out:
                self.logger.log(Level.WARNING, "Detection plugin timed out: " + plugin_name)
                continue
            if result.exit_code == 0:
                return os_key
        return None

    def _sanitize_plugin_name(self, name):
        buffer = []
        for ch in name:
            if ch.isalnum() or ch in [".", "_", "-"]:
                buffer.append(ch)
            else:
                buffer.append("_")
        return "".join(buffer)

    def _reset_file(self, path):
        if path is None:
            return
        file_obj = File(path)
        if file_obj.exists():
            file_obj.delete()

    def _append_log(self, src_path, dest_path, header):
        if src_path is None:
            return
        src_file = File(src_path)
        if not src_file.exists():
            return
        dest_file = File(dest_path)
        parent = dest_file.getParentFile()
        if parent is not None and not parent.exists():
            parent.mkdirs()
        reader = None
        writer = None
        try:
            reader = BufferedReader(InputStreamReader(FileInputStream(src_file), "UTF-8"))
            writer = BufferedWriter(OutputStreamWriter(FileOutputStream(dest_file, True), "UTF-8"))
            writer.write(header)
            writer.write("\n")
            while True:
                line = reader.readLine()
                if line is None:
                    break
                writer.write(line)
                writer.write("\n")
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to append stderr log: " + str(ex))
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            src_file.delete()

    def _ensure_file_has_message(self, file_path, message):
        file_obj = File(file_path)
        parent = file_obj.getParentFile()
        if parent is not None and not parent.exists():
            parent.mkdirs()
        writer = None
        try:
            writer = BufferedWriter(OutputStreamWriter(FileOutputStream(file_obj, True), "UTF-8"))
            writer.write(message)
            writer.write("\n")
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to write fallback message: " + str(ex))
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    def _write_timeout(self, timeout_path, plugin_name, renderer):
        file_obj = File(timeout_path)
        parent = file_obj.getParentFile()
        if parent is not None and not parent.exists():
            parent.mkdirs()
        writer = None
        try:
            writer = BufferedWriter(OutputStreamWriter(FileOutputStream(file_obj, True), "UTF-8"))
            writer.write("Timeout while running {0} ({1})\n".format(plugin_name, renderer))
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to record timeout note: " + str(ex))
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

class Vol3IngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.logger = Logger.getLogger("Vol3IngestModuleFactory")

    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return "Runs Volatility 3 as an external process and records findings."

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def hasIngestJobSettingsPanel(self):
        return True

    def getDefaultIngestJobSettings(self):
        return Vol3JobSettings()

    def getIngestJobSettingsPanel(self, settings):
        if settings is None:
            settings = Vol3JobSettings()
        config_path = os.path.join(_module_directory(), "resources", "config.ini")
        config = Vol3Config(config_path, self.logger)
        config.load()
        return Vol3SettingsPanel(settings, config, self.logger)

    def createDataSourceIngestModule(self, settings):
        if settings is None or not isinstance(settings, Vol3JobSettings):
            if settings is not None and hasattr(settings, "serialize"):
                try:
                    serialized = settings.serialize()
                except Exception:
                    serialized = None
                new_settings = Vol3JobSettings()
                if serialized is not None:
                    try:
                        new_settings.deserialize(serialized)
                    except Exception:
                        pass
                settings = new_settings
            else:
                settings = Vol3JobSettings()
        return Vol3DataSourceIngestModule(settings)



