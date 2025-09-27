# -*- coding: utf-8 -*-
import os
import sys
import json
import inspect
import threading
import time

from java.io import File, FileInputStream, BufferedReader, InputStreamReader, FileOutputStream, OutputStreamWriter, BufferedWriter, IOException
from java.lang import ProcessBuilder, System
from java.util.logging import Level
from java.util import ArrayList
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
try:
    from org.sleuthkit.autopsy.coreutils import ContentUtils as AutopsyContentUtils
except Exception:
    AutopsyContentUtils = None
from org.sleuthkit.datamodel import ReadContentInputStream, BlackboardArtifact, BlackboardAttribute, SleuthkitCase, TskData
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from java.io import FileOutputStream, BufferedOutputStream
try:
    from org.apache.commons.io import IOUtils as ApacheIOUtils
except Exception:
    ApacheIOUtils = None
from jarray import zeros as _jbytes

try:
    unicode
except NameError:
    unicode = str

MODULE_NAME = "Volatility 3 Ingest Module"
MODULE_VERSION = "1.0"
OS_WINDOWS = "windows"
OS_LINUX = "linux"
IngestModuleException = IngestModule.IngestModuleException
OS_MAC = "mac"
CASE_MODULE_OUTPUT_TOKEN = "CASE_MODULE_OUTPUT"
SETTINGS_LOGGER = Logger.getLogger("Vol3JobSettings")


# Lightweight debug file logging to help diagnose issues when
# Autopsy UI/logs don't show enough detail (e.g., before case exists
# or when exceptions are swallowed by the platform).
def _debug_log_path():
    try:
        tmp = System.getProperty("java.io.tmpdir")
        return File(tmp, "Autopsy-Vol3-debug.log")
    except Exception:
        # Last resort: current directory
        return File("Autopsy-Vol3-debug.log")


def _safe_debug_log(message):
    try:
        if message is None:
            message = ""
        # Ensure text is unicode for Jython
        try:
            txt = unicode(message)
        except Exception:
            txt = str(message)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = u"[{0}] {1}\n".format(stamp, txt)
        target = _debug_log_path()
        parent = target.getParentFile()
        if parent is not None and not parent.exists():
            try:
                parent.mkdirs()
            except Exception:
                pass
        writer = None
        try:
            writer = BufferedWriter(OutputStreamWriter(FileOutputStream(target, True), "UTF-8"))
            writer.write(line)
            writer.flush()
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
    except Exception:
        # Never raise from the debug logger
        pass


def _msg_type_info():
    try:
        return IngestMessage.MessageType.INFO
    except Exception:
        return None


def _msg_type_data():
    try:
        return IngestMessage.MessageType.DATA
    except Exception:
        return _msg_type_info()


def _msg_type_warning():
    # Fallback to INFO if WARNING is unavailable
    try:
        return IngestMessage.MessageType.WARNING
    except Exception:
        return _msg_type_info()


def _msg_type_error():
    # Fallback to INFO if ERROR is unavailable
    try:
        return IngestMessage.MessageType.ERROR
    except Exception:
        return _msg_type_info()


DEFAULT_PLUGIN_WHITELISTS = {
    OS_WINDOWS: ['windows.info', 'windows.pslist', 'windows.dlllist', 'windows.handles', 'windows.netscan'],
    OS_LINUX: ['linux.pslist', 'linux.lsmod'],
    OS_MAC: ['mac.pslist']
}

OS_DETECTION_SEQUENCE = [
    (OS_WINDOWS, "windows.info", "json"),
    # Top-level 'banners' plugin identifies Linux banners without symbols
    (OS_LINUX, "banners", "json"),
    # mac.pslist requires symbols; if symbols are missing, this step will fail gracefully
    (OS_MAC, "mac.pslist", "json")
]


def _module_directory():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        frame = inspect.currentframe()
        return os.path.dirname(os.path.abspath(inspect.getfile(frame)))


def _resolve_plugin_whitelist(config, os_key):
    if os_key == OS_WINDOWS:
        values = config.get_list("plugins.win", "whitelist")
    elif os_key == OS_LINUX:
        values = config.get_list("plugins.lin", "whitelist")
    elif os_key == OS_MAC:
        values = config.get_list("plugins.mac", "whitelist")
    else:
        values = []
    if values is None or len(values) == 0:
        defaults = DEFAULT_PLUGIN_WHITELISTS.get(os_key, [])
        return list(defaults)
    return values


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
        self.max_bytes = max_bytes if max_bytes is not None else 0
        self.append_mode = append_mode
        self.truncated = False
        self.error = None

    def run(self):
        out_stream = None
        try:
            if self.target_path is not None:
                file_obj = File(self.target_path)
                parent = file_obj.getParentFile()
                if parent is not None and not parent.exists():
                    parent.mkdirs()
                out_stream = BufferedOutputStream(FileOutputStream(file_obj, self.append_mode))
            buf = _jbytes(8192, 'b')
            total = 0
            while True:
                n = self.input_stream.read(buf)
                if n == -1:
                    break
                if out_stream is not None:
                    if self.max_bytes > 0 and (total + n) > self.max_bytes:
                        remain = self.max_bytes - total
                        if remain > 0:
                            out_stream.write(buf, 0, remain)
                            total += remain
                        self.truncated = True
                        # Drain the rest without writing
                        while self.input_stream.read(buf) != -1:
                            pass
                        break
                    else:
                        out_stream.write(buf, 0, n)
                        total += n
            if out_stream is not None:
                out_stream.flush()
        except Exception as ex:
            self.error = str(ex)
        finally:
            try:
                self.input_stream.close()
            except Exception:
                pass
            if out_stream is not None:
                try:
                    out_stream.close()
                except Exception:
                    pass


class Vol3Runner(object):
    def __init__(self, logger, python_exe, volatility_exe, timeout_sec, max_stdout_bytes, extra_global_opts=None, launch_mode=u"script"):
        self.logger = logger
        self.python_exe = python_exe
        self.volatility_exe = volatility_exe
        self.timeout_sec = timeout_sec
        self.max_stdout_bytes = max_stdout_bytes
        # Additional Volatility global options (e.g., -v, --offline, -u URL, -s DIRS, -p DIRS, --cache-path PATH)
        if extra_global_opts is None:
            self.extra_global_opts = []
        else:
            self.extra_global_opts = list(extra_global_opts)
        # Optional path to append executed commands for debugging
        self.command_log_path = None
        # Launch mode: 'script' (python vol.py), 'module' (python -m volatility3), 'console' (vol.exe/vol)
        mode = (launch_mode or u"script").strip().lower()
        if mode not in (u"script", u"module", u"console"):
            mode = u"script"
        self.launch_mode = mode

    def _to_unicode(self, value):
        if value is None:
            return u""
        if isinstance(value, unicode):
            return value
        return unicode(value)

    def run_plugin(self, dump_path, plugin_name, renderer, stdout_path, stderr_path, timeout_sec, cancel_check):
        # Volatility 3 expects global options before the plugin name.
        cmd = self._build_base_cmd()
        for opt in self.extra_global_opts:
            cmd.append(self._to_unicode(opt))
        cmd.extend([u'--renderer', self._to_unicode(renderer), u'-f', self._to_unicode(dump_path), self._to_unicode(plugin_name)])
        self._append_command_log(u"PLUGIN {0} ({1}) :: ".format(self._to_unicode(plugin_name), self._to_unicode(renderer)) + u" ".join(cmd))
        return self._execute(cmd, stdout_path, stderr_path, timeout_sec, cancel_check)

    def run_detection(self, dump_path, plugin_name, renderer, timeout_sec, cancel_check):
        # Same ordering as run_plugin: global options first, then plugin
        cmd = self._build_base_cmd()
        for opt in self.extra_global_opts:
            cmd.append(self._to_unicode(opt))
        cmd.extend([u'--renderer', self._to_unicode(renderer), u'-f', self._to_unicode(dump_path), self._to_unicode(plugin_name)])
        self._append_command_log(u"DETECT {0} ({1}) :: ".format(self._to_unicode(plugin_name), self._to_unicode(renderer)) + u" ".join(cmd))
        return self._execute(cmd, None, None, timeout_sec, cancel_check)

    def verify_binaries(self):
        cmd = self._build_base_cmd()
        cmd.append(u'--help')
        self._append_command_log(u"VERIFY :: " + u" ".join(cmd))
        result = self._execute(cmd, None, None, 30, None)
        if result is not None and result.exit_code != 0 and self.logger is not None:
            try:
                self.logger.log(Level.WARNING, "Volatility help returned non-zero exit code: {0}".format(result.exit_code))
            except Exception:
                pass
        return result

    def query_available_plugins(self, timeout_sec):
        # In Volatility 3, the global help (-h) lists available plugins.
        # Using -h is more portable than legacy --info.
        cmd = self._build_base_cmd()
        cmd.append(u'-h')
        self._append_command_log(u"PLUGINS-QUERY :: " + u" ".join(cmd))
        try:
            _safe_debug_log(u"[settings] Query plugins command: " + u" ".join(cmd))
        except Exception:
            pass
        stdout_tmp = File.createTempFile("vol3_plugins", ".txt")
        stderr_tmp = File.createTempFile("vol3_plugins_err", ".txt")
        stdout_tmp.deleteOnExit()
        stderr_tmp.deleteOnExit()
        try:
            result = self._execute(cmd, stdout_tmp.getAbsolutePath(), stderr_tmp.getAbsolutePath(), timeout_sec, None)
            output = self._read_text_file(stdout_tmp)
            error_output = self._read_text_file(stderr_tmp)
            try:
                _safe_debug_log(u"[settings] Query result: exit={0} timed_out={1} err?={2}".format(
                    result.exit_code if result is not None else None,
                    result.timed_out if result is not None else None,
                    (len(error_output) > 0) if error_output is not None else False))
                if error_output is not None and len(error_output) > 0:
                    _safe_debug_log(u"[settings] stderr (first 300 chars): " + error_output[:300])
            except Exception:
                pass
            return (result, output, error_output)
        finally:
            stdout_tmp.delete()
            stderr_tmp.delete()

    def _build_base_cmd(self):
        # Determines how to invoke Volatility 3 based on launch_mode
        if self.launch_mode == u"module":
            return [self._to_unicode(self.python_exe), u'-m', u'volatility3']
        if self.launch_mode == u"console":
            return [self._to_unicode(self.volatility_exe)]
        # default 'script'
        return [self._to_unicode(self.python_exe), self._to_unicode(self.volatility_exe)]

    def set_command_log_path(self, path):
        if path is None:
            self.command_log_path = None
        else:
            self.command_log_path = self._to_unicode(path)

    def _append_command_log(self, text):
        if self.command_log_path is None or text is None:
            return
        try:
            file_obj = File(self.command_log_path)
            parent = file_obj.getParentFile()
            if parent is not None and not parent.exists():
                parent.mkdirs()
            writer = None
            try:
                writer = BufferedWriter(OutputStreamWriter(FileOutputStream(file_obj, True), "UTF-8"))
                writer.write(text)
                writer.write("\n")
                writer.flush()
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
        except Exception:
            # Swallow logging failures to avoid affecting main run
            pass


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

    def _execute(self, cmd, stdout_path, stderr_path, timeout_sec, cancel_check):
        result = PluginExecutionResult()
        result.stdout_path = stdout_path
        result.stderr_path = stderr_path
        if timeout_sec is None or timeout_sec <= 0:
            timeout_sec = self.timeout_sec
        if self.logger is not None:
            try:
                self.logger.log(Level.INFO, "Executing command: " + " ".join(cmd))
            except Exception:
                pass
        try:
            _safe_debug_log(u"[runner] Executing: " + u" ".join([unicode(x) for x in cmd]))
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
            builder = ProcessBuilder(cmd)
            try:
                _safe_debug_log(u"[runner] ProcessBuilder created. Starting process...")
            except Exception:
                pass
            process = builder.start()
            try:
                _safe_debug_log(u"[runner] Process started. Collecting streams...")
            except Exception:
                pass
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
        try:
            _safe_debug_log(u"[runner] Finished: exit={0} timeout={1} cancelled={2} err={3}".format(
                result.exit_code, result.timed_out, result.cancelled, unicode(result.error) if result.error is not None else u""))
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
            return _resolve_plugin_whitelist(self.config, OS_WINDOWS)
        if os_key == OS_LINUX:
            return _resolve_plugin_whitelist(self.config, OS_LINUX)
        if os_key == OS_MAC:
            return _resolve_plugin_whitelist(self.config, OS_MAC)
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
        try:
            _safe_debug_log("[settings] Constructing settings panel")
        except Exception:
            pass
        self.available_plugins = {
            OS_WINDOWS: _resolve_plugin_whitelist(self.config, OS_WINDOWS),
            OS_LINUX: _resolve_plugin_whitelist(self.config, OS_LINUX),
            OS_MAC: _resolve_plugin_whitelist(self.config, OS_MAC)
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
        try:
            _safe_debug_log("[settings] Settings panel ready")
        except Exception:
            pass

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
            # Help lists often include the class name (e.g., windows.pslist.PsList).
            # Volatility CLI accepts the plugin path without the class suffix (windows.pslist).
            if "." in token:
                base = token.rsplit(".", 1)[0]
                if base not in names:
                    names.append(base)
        return names

    def _refresh_plugins(self):
        python_path = self.python_field.getText().strip()
        vol_path = self.vol_field.getText().strip()
        # Determine launch mode: support console 'vol' without python
        launch_mode = u"script"
        if len(vol_path) == 0:
            vol_path = u"vol"
            launch_mode = u"console"
        else:
            low = vol_path.lower()
            if low.endswith('.py'):
                launch_mode = u"script"
            else:
                launch_mode = u"console"
        try:
            _safe_debug_log(u"[settings] Refresh pressed. mode={0} python={1} vol={2}".format(launch_mode, python_path, vol_path))
        except Exception:
            pass
        runner = Vol3Runner(self.logger, python_path, vol_path, self.default_timeout, self.default_max_stdout, None, launch_mode)
        try:
            result, output, error_output = runner.query_available_plugins(min(120, self.default_timeout))
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to query plugins: " + str(ex))
            try:
                _safe_debug_log(u"[settings] Exception during query: " + unicode(ex))
            except Exception:
                pass
            self._set_status("Failed to refresh plugins: " + str(ex), Level.WARNING)
            return
        if result.timed_out:
            self._set_status("Plugin query timed out", Level.WARNING)
            try:
                _safe_debug_log(u"[settings] Query timed out")
            except Exception:
                pass
            return
        plugins = self._parse_plugins_from_text(output)
        try:
            _safe_debug_log(u"[settings] Parsed plugin names: {0}".format(len(plugins)))
        except Exception:
            pass
        if len(plugins) == 0:
            self._set_status("No plugin names found", Level.WARNING)
            try:
                if error_output is not None and len(error_output) > 0:
                    _safe_debug_log(u"[settings] stderr present when no names: " + error_output[:300])
            except Exception:
                pass
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
            # In console mode python may be unused
            pass
        else:
            if not File(python_path).exists():
                warnings.append("Python executable path does not exist: " + python_path)
        vol_path = settings.getVolatilityExe()
        if vol_path is None or len(vol_path) == 0:
            warnings.append("Volatility path is empty (use 'vol' in console mode or set vol.py path).")
        else:
            # If using console command 'vol', skip file existence check
            if vol_path.strip().lower() != "vol" and not File(vol_path).exists():
                warnings.append("Volatility path does not exist: " + vol_path)
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
        self.errors_summary_path = None
        # Temporary exports to clean up (e.g., extracted memory image)
        self._temp_exports = []
        # Cache for created/located 'Volatility3' directories per data source id
        self._vol_dir_cache = {}
        self._current_vol_dir = None
        # Registration mode for outputs: 'derived' (default), 'local', or 'both'
        self.register_mode = 'derived'

    def _add_local_file_robust(self, sk, parent, name, size, ts, path, mime):
        # Tries multiple SleuthkitCase.addLocalFile signatures across versions
        # Returns AbstractFile or None
        try:
            # 14-arg variant with EncodingType at end
            try:
                lf = sk.addLocalFile(name, size, ts, ts, ts, ts, True,
                                     path, None, None, None, mime, parent,
                                     SleuthkitCase.EncodingType.NONE)
                if lf is not None:
                    return lf
            except Exception:
                pass
            # 14-arg variant with EncodingType before mime/parent (alternative ordering)
            try:
                lf = sk.addLocalFile(name, size, ts, ts, ts, ts, True,
                                     path, None, None, None,
                                     SleuthkitCase.EncodingType.NONE, mime, parent)
                if lf is not None:
                    return lf
            except Exception:
                pass
            # 11-arg variant: omit hashes and mime
            try:
                lf = sk.addLocalFile(name, size, ts, ts, ts, ts, True,
                                     path, parent)
                if lf is not None:
                    return lf
            except Exception:
                pass
            # 12-arg variant: include mime only
            try:
                lf = sk.addLocalFile(name, size, ts, ts, ts, ts, True,
                                     path, mime, parent)
                if lf is not None:
                    return lf
            except Exception:
                pass
        except Exception:
            pass
        return None

    def startUp(self, context):
        _safe_debug_log("[ingest] startUp() entered")
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
        # Determine launch mode: script (python vol.py), module (python -m volatility3), console (vol)
        launch_mode = self.config.get("runtime", "launch_mode", "").strip().lower()
        if launch_mode not in ("script", "module", "console", ""):
            launch_mode = "script"
        if launch_mode == "":
            # Auto-detect
            if vol_path is None or len(vol_path) == 0:
                launch_mode = "module"
            else:
                if vol_path.lower().endswith(".py"):
                    launch_mode = "script"
                else:
                    launch_mode = "console"
        # Validate paths per launch mode
        if launch_mode in ("script", "module"):
            if python_path is None or len(python_path) == 0:
                try:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(_msg_type_error(), MODULE_NAME,
                                                    "Python executable path is not configured (startUp)"))
                except Exception:
                    pass
                raise IngestModuleException("Python executable path is not configured")
        if launch_mode == "script":
            if vol_path is None or len(vol_path) == 0:
                try:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(_msg_type_error(), MODULE_NAME,
                                                    "Volatility script path is not configured (startUp)"))
                except Exception:
                    pass
                raise IngestModuleException("Volatility script path is not configured")
        self.python_exe = python_path
        self.vol_exe = vol_path
        self.logger.log(Level.INFO, "Volatility runner configured: mode={0}, python={1}, vol={2}".format(launch_mode, self.python_exe, self.vol_exe))
        try:
            _safe_debug_log(u"[ingest] Configured runner: mode={0} python={1} vol={2}".format(launch_mode, self.python_exe, self.vol_exe))
        except Exception:
            pass

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
        # Minimum candidate size for detected memory image (in MB)
        try:
            min_mb = self.config.get_int("limits", "min_image_mb", 8)
        except Exception:
            min_mb = 8
        if min_mb <= 0:
            min_mb = 8
        self.min_candidate_bytes = min_mb * 1024 * 1024

        # Whether to attach outputs as a separate Local Files data source
        try:
            attach_cfg = self.config.get("output", "attach_as_data_source", "false")
        except Exception:
            attach_cfg = "false"
        try:
            self.attach_as_ds = (attach_cfg is not None) and (attach_cfg.strip().lower() in ("1", "true", "yes", "on"))
        except Exception:
            self.attach_as_ds = False
        try:
            _safe_debug_log(u"[ingest] attach_as_ds setting: " + (u"true" if self.attach_as_ds else u"false"))
        except Exception:
            pass

        # Read registration mode for file visibility handling
        try:
            reg_mode = self.config.get("output", "register_mode", "derived")
        except Exception:
            reg_mode = "derived"
        try:
            reg_mode_l = (reg_mode or "").strip().lower()
            if reg_mode_l not in ("derived", "local", "both"):
                reg_mode_l = "derived"
            self.register_mode = reg_mode_l
        except Exception:
            self.register_mode = "derived"
        try:
            _safe_debug_log(u"[ingest] register_mode: " + self.register_mode)
        except Exception:
            pass

        extra_opts = self._build_extra_opts()
        self.runner = Vol3Runner(self.logger, self.python_exe, self.vol_exe, self.timeout_sec, self.max_stdout_bytes, extra_opts, launch_mode)
        try:
            verify_result = self.runner.verify_binaries()
            try:
                if verify_result is not None and verify_result.exit_code != 0:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(_msg_type_warning(), MODULE_NAME,
                                                    "Volatility '--help' returned non-zero exit code: {0}".format(verify_result.exit_code)))
            except Exception:
                pass
        except Exception as ex:
            self.logger.log(Level.SEVERE, "Volatility verification failed: " + str(ex))
            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(_msg_type_error(), MODULE_NAME,
                                                "Volatility verification failed (--help): " + unicode(ex)))
            except Exception:
                pass
            try:
                _safe_debug_log(u"[ingest] verify_binaries failed: " + unicode(ex))
            except Exception:
                pass
            raise IngestModuleException("Unable to execute Volatility 3 (--help failed): " + str(ex))

        self.plugin_plan = Vol3PluginPlan(self.config, self.settings)
        try:
            _safe_debug_log("[ingest] startUp() completed successfully")
        except Exception:
            pass

    def process(self, dataSource, progressBar):
        _safe_debug_log("[ingest] process() entered")
        dump_path = None
        try:
            dump_path = dataSource.getLocalAbsPath()
        except Exception:
            dump_path = None
        self.logger.log(Level.INFO, "process() invoked for {0}, local path: {1}".format(dataSource.getName(), dump_path))
        ingest_services = IngestServices.getInstance()
        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Volatility module invoked for " + dataSource.getName()))
        need_fallback = False
        if dump_path is None or len(unicode(dump_path)) == 0:
            need_fallback = True
        else:
            df = File(dump_path)
            if not df.exists():
                need_fallback = True
        if need_fallback:
            try:
                ingest_services.postMessage(IngestMessage.createMessage(_msg_type_warning(), MODULE_NAME,
                    "No direct local path from data source; attempting to locate and export a memory image"))
            except Exception:
                pass
            try:
                dump_path = self._locate_and_export_image(dataSource)
            except Exception as ex:
                dump_path = None
                try:
                    _safe_debug_log(u"[ingest] export candidate failed: " + unicode(ex))
                except Exception:
                    pass
            if dump_path is None:
                self.logger.log(Level.SEVERE, "Unable to resolve a memory image from data source")
                try:
                    ingest_services.postMessage(IngestMessage.createMessage(_msg_type_error(), MODULE_NAME,
                        "Unable to resolve a memory image from data source (no suitable files found)"))
                except Exception:
                    pass
                return DataSourceIngestModule.ProcessResult.ERROR
            else:
                try:
                    ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                        "Exported candidate memory image for analysis: " + dump_path))
                except Exception:
                    pass

        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                                                                "Volatility 3 run started for " + dataSource.getName()))

        self.report_root_dir = self._prepare_output_root()
        if self.report_root_dir is None:
            self.logger.log(Level.SEVERE, "Failed to prepare report output directory")
            try:
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(_msg_type_error(), MODULE_NAME,
                                                "Failed to prepare report output directory"))
            except Exception:
                pass
            try:
                _safe_debug_log("[ingest] Failed to prepare report root")
            except Exception:
                pass
            return DataSourceIngestModule.ProcessResult.ERROR

        self.json_dir = File(self.report_root_dir, "json")
        self.txt_dir = File(self.report_root_dir, "txt")
        self.logs_dir = File(self.report_root_dir, "logs")
        self.json_dir.mkdirs()
        self.txt_dir.mkdirs()
        self.logs_dir.mkdirs()
        # Set up debugging/diagnostics files
        try:
            commands_log = File(self.logs_dir, "commands.log").getAbsolutePath()
            self.runner.set_command_log_path(commands_log)
            try:
                _safe_debug_log(u"[ingest] commands.log at: " + commands_log)
            except Exception:
                pass
        except Exception:
            pass
        self.errors_summary_path = File(self.logs_dir, "errors_summary.txt").getAbsolutePath()
        self._reset_file(self.errors_summary_path)
        self._write_run_diagnostics(False)

        detected_os = self._detect_operating_system(dump_path)
        self.last_detected_os = detected_os
        if detected_os is not None:
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Detected operating system: " + detected_os))
        else:
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Operating system detection failed; defaulting to selected plugins"))
        if detected_os is not None:
            self.logger.log(Level.INFO, "Detected operating system: " + detected_os)
        else:
            self.logger.log(Level.INFO, "Operating system detection failed; using selected plugins")

        plugins = self.plugin_plan.compute_plugins(detected_os)
        try:
            _safe_debug_log(u"[ingest] Plugins planned: {0}".format(len(plugins) if plugins is not None else 0))
        except Exception:
            pass
        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Planning to run " + str(len(plugins)) + " plugins"))
        if plugins is None or len(plugins) == 0:
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "No plugins selected for execution"))
            self.logger.log(Level.WARNING, "No plugins selected for execution")
            return DataSourceIngestModule.ProcessResult.OK

        total_steps = len(plugins) * 2
        if total_steps > 0:
            progressBar.switchToDeterminate(total_steps)
        else:
            progressBar.switchToIndeterminate()
        current_step = 0
        progressBar.progress(current_step)
        self.success_count = 0
        self.failure_count = 0
        self.timeout_count = 0

        plugin_list_log = ", ".join(plugins)
        if self.logger is not None:
            try:
                self.logger.log(Level.INFO, "Planned plugins (" + str(len(plugins)) + "): " + plugin_list_log)
            except Exception:
                pass

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
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Preparing " + plugin_name))
            plugin_success = True
            plugin_timeout = False

            self.logger.log(Level.INFO, "Running plugin {0} (jsonl)".format(plugin_name))
            try:
                _safe_debug_log(u"[ingest] Running (jsonl): " + plugin_name)
            except Exception:
                pass
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Running " + plugin_name + " (jsonl)"))
            json_result = self.runner.run_plugin(dump_path, plugin_name, "jsonl", json_path, stderr_json_tmp, self.timeout_sec, self._is_cancelled)
            # Record error details before temp stderr is appended & deleted
            self._record_error(plugin_name, "jsonl", stderr_json_tmp, json_result)
            self._append_log(stderr_json_tmp, stderr_final, "[JSONL] " + plugin_name)
            self._record_error(plugin_name, "jsonl", stderr_json_tmp, json_result)
            current_step += 1
            progressBar.progress(current_step)
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

            self.logger.log(Level.INFO, "Running plugin {0} (pretty)".format(plugin_name))
            try:
                _safe_debug_log(u"[ingest] Running (pretty): " + plugin_name)
            except Exception:
                pass
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, "Running " + plugin_name + " (pretty)"))
            txt_result = self.runner.run_plugin(dump_path, plugin_name, "pretty", txt_path, stderr_txt_tmp, self.timeout_sec, self._is_cancelled)
            # Record error details before temp stderr is appended & deleted
            self._record_error(plugin_name, "pretty", stderr_txt_tmp, txt_result)
            self._append_log(stderr_txt_tmp, stderr_final, "[PRETTY] " + plugin_name)
            self._record_error(plugin_name, "pretty", stderr_txt_tmp, txt_result)
            current_step += 1
            progressBar.progress(current_step)
            if txt_result.cancelled:
                self.logger.log(Level.INFO, "Processing cancelled during plugin " + plugin_name)
                return DataSourceIngestModule.ProcessResult.OK
            if txt_result.timed_out:
                plugin_timeout = True
                plugin_success = False
                self._write_timeout(timeout_note, plugin_name, "pretty")
            if txt_result.exit_code != 0:
                plugin_success = False
                self._ensure_file_has_message(txt_path, "no results")
            if txt_result.error is not None:
                plugin_success = False
                self.logger.log(Level.WARNING, "Error during plugin {0} (pretty): {1}".format(plugin_name, txt_result.error))
            # Ensure TXT exists and is non-empty
            try:
                _f = File(txt_path)
                if _f is None or (not _f.exists()) or _f.length() == 0:
                    self._ensure_file_has_message(txt_path, "no output")
            except Exception:
                pass
            # Do not add TXT to Reports here; TXT will be attached under the data source instead

            status_message = "Finished " + plugin_name
            if plugin_success and not plugin_timeout:
                status_message += " (success)"
            elif plugin_timeout:
                status_message += " (timeout)"
            else:
                status_message += " (issues)"
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, status_message))
            status_message = "Finished " + plugin_name
            if plugin_success and not plugin_timeout:
                status_message += " (success)"
            elif plugin_timeout:
                status_message += " (timeout)"
            else:
                status_message += " (issues)"
            ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME, status_message))
            if plugin_timeout:
                self.timeout_count += 1
            if plugin_success:
                self.success_count += 1
            else:
                self.failure_count += 1
            # Register outputs under current Data Source only if not attaching as a separate DS
            if not getattr(self, 'attach_as_ds', True):
                try:
                    _safe_debug_log(u"[ingest] per-plugin registration under DS for: " + plugin_name)
                except Exception:
                    pass
                try:
                    # Skip if a file with the same name already exists in the data source
                    base_name = self._sanitize_plugin_name(plugin_name).split(".")[-1] + ".txt"
                    _df = self._create_derived_file(dataSource, plugin_name, txt_path)
                    if _df is None:
                        try:
                            self._register_local_txt(dataSource, File(txt_path))
                        except Exception:
                            pass
                except Exception:
                    try:
                        self._register_local_txt(dataSource, File(txt_path))
                    except Exception:
                        pass
            else:
                try:
                    _safe_debug_log(u"[ingest] deferring registration; will attach as separate DS")
                except Exception:
                    pass
            # Post TXT as a blackboard artifact (best-effort)
            try:
                json_count = self._count_lines(json_path)
            except Exception:
                json_count = -1
            try:
                self._post_txt_artifact(dataSource, plugin_name, txt_path, json_count, plugin_success, plugin_timeout)
            except Exception:
                pass

            # Fallback: if pslist/pstree returned no records, try psscan (best-effort)
            try:
                need_fb = False
                if plugin_name in ("windows.pslist", "windows.pstree"):
                    # Empty JSONL or empty TXT implies nothing rendered
                    need_fb = (json_count is None) or (json_count <= 0)
                    try:
                        txt_file_chk = File(txt_path)
                        if txt_file_chk is None or (not txt_file_chk.exists()) or (txt_file_chk.length() == 0):
                            need_fb = True
                    except Exception:
                        pass
                if need_fb:
                    try:
                        suffix = plugin_name.split(".")[-1] if "." in plugin_name else plugin_name
                    except Exception:
                        suffix = "orig"
                    fb_label = u"windows.psscan (fallback for {0})".format(suffix)
                    fb_safe = self._sanitize_plugin_name("windows.psscan_for_" + suffix)
                    fb_json = File(self.json_dir, fb_safe + ".jsonl").getAbsolutePath()
                    fb_txt = File(self.txt_dir, fb_safe + ".txt").getAbsolutePath()
                    fb_stderr_final = File(self.logs_dir, fb_safe + ".stderr.txt").getAbsolutePath()
                    fb_stderr_json_tmp = File(self.logs_dir, fb_safe + ".stderr.json.tmp").getAbsolutePath()
                    fb_stderr_txt_tmp = File(self.logs_dir, fb_safe + ".stderr.text.tmp").getAbsolutePath()
                    fb_timeout = File(self.logs_dir, fb_safe + ".timeout.txt").getAbsolutePath()
                    # Reset output files
                    for p in (fb_json, fb_txt, fb_stderr_final, fb_stderr_json_tmp, fb_stderr_txt_tmp, fb_timeout):
                        try:
                            self._reset_file(p)
                        except Exception:
                            pass
                    ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                                              u"Running fallback: psscan for {0}".format(plugin_name)))
                    # Run JSONL
                    fb_success = True
                    fb_timed_out = False
                    fb_json_res = self.runner.run_plugin(dump_path, "windows.psscan", "jsonl", fb_json, fb_stderr_json_tmp, self.timeout_sec, self._is_cancelled)
                    self._record_error(fb_label, "jsonl", fb_stderr_json_tmp, fb_json_res)
                    self._append_log(fb_stderr_json_tmp, fb_stderr_final, "[JSONL] " + fb_label)
                    if fb_json_res.cancelled:
                        return DataSourceIngestModule.ProcessResult.OK
                    if fb_json_res.timed_out:
                        fb_timed_out = True
                        fb_success = False
                        self._write_timeout(fb_timeout, fb_label, "jsonl")
                    if fb_json_res.exit_code != 0 or fb_json_res.error is not None:
                        fb_success = False
                    # Run pretty
                    fb_txt_res = self.runner.run_plugin(dump_path, "windows.psscan", "pretty", fb_txt, fb_stderr_txt_tmp, self.timeout_sec, self._is_cancelled)
                    self._record_error(fb_label, "pretty", fb_stderr_txt_tmp, fb_txt_res)
                    self._append_log(fb_stderr_txt_tmp, fb_stderr_final, "[PRETTY] " + fb_label)
                    if fb_txt_res.cancelled:
                        return DataSourceIngestModule.ProcessResult.OK
                    if fb_txt_res.timed_out:
                        fb_timed_out = True
                        fb_success = False
                        self._write_timeout(fb_timeout, fb_label, "pretty")
                    if fb_txt_res.exit_code != 0 or fb_txt_res.error is not None:
                        fb_success = False
                    # Register and post artifact
                    try:
                        fb_json_count = self._count_lines(fb_json)
                    except Exception:
                        fb_json_count = -1
                    try:
                        self._create_derived_file(dataSource, fb_label, fb_txt)
                    except Exception:
                        pass
                    try:
                        self._post_txt_artifact(dataSource, fb_label, fb_txt, fb_json_count, fb_success, fb_timed_out)
                    except Exception:
                        pass
            except Exception:
                pass

        # Attach outputs either under current DS or as a dedicated Local Files DS
        if getattr(self, 'attach_as_ds', True):
            created_ok = False
            try:
                created_ok = self._attach_outputs_as_data_source(dataSource)
            except Exception:
                created_ok = False
            if not created_ok:
                # Fallback to registering under current DS to avoid losing outputs
                try:
                    self._sync_all_txt_to_fileset(dataSource)
                except Exception:
                    pass
        else:
            # Final sweep to register any TXT not yet added to File Views under current DS
            try:
                self._sync_all_txt_to_fileset(dataSource)
            except Exception:
                pass
        progressBar.progress(total_steps)
        summary = "Volatility 3 finished for {0}. Success: {1}, Failed: {2}, Timed out: {3}. Output: {4}".format(
            dataSource.getName(), self.success_count, self.failure_count, self.timeout_count,
            self.report_root_dir.getAbsolutePath())
        ingest_services.postMessage(IngestMessage.createMessage(IngestMessage.MessageType.DATA, MODULE_NAME, summary))
        self.logger.log(Level.INFO, summary)
        try:
            _safe_debug_log(u"[ingest] process() completed: " + summary)
        except Exception:
            pass
        try:
            self._cleanup_temp_exports()
        except Exception:
            pass
        return DataSourceIngestModule.ProcessResult.OK

    def _locate_and_export_image(self, dataSource):
        try:
            fm = Case.getCurrentCase().getServices().getFileManager()
        except Exception as ex:
            self.logger.log(Level.WARNING, "Failed to acquire FileManager: " + unicode(ex))
            return None
        patterns = [
            "%.raw", "%.mem", "%.bin", "%.dd", "%.dmp", "%.vmem", "%.vmsn", "%.dump", "%.aff4", "%.lime",
            "%.e01", "%.s01", "%.001", "%.ad1",
            "hiberfil.sys", "HIBERFIL.SYS", "memory.dmp", "MEMORY.DMP", "pagefile.sys", "PAGEFILE.SYS", "swapfile.sys", "SWAPFILE.SYS"
        ]
        candidates = []
        try:
            for pat in patterns:
                try:
                    found = fm.findFiles(dataSource, "%", pat)
                    if found is not None:
                        for f in found:
                            candidates.append(f)
                except Exception:
                    pass
            if len(candidates) == 0:
                try:
                    found_all = fm.findFiles(dataSource, "%", "%")
                    if found_all is not None:
                        for f in found_all:
                            name = f.getName().lower()
                            if name.endswith((".raw", ".mem", ".bin", ".dd", ".dmp", ".vmem", ".vmsn", ".dump", ".aff4", ".lime", ".e01", ".s01", ".001", ".ad1")) or name in ("hiberfil.sys", "memory.dmp", "pagefile.sys", "swapfile.sys"):
                                candidates.append(f)
                            else:
                                try:
                                    size_val = f.getSize()
                                    if size_val is not None and size_val >= self.min_candidate_bytes:
                                        candidates.append(f)
                                except Exception:
                                    pass
                except Exception:
                    pass
        except Exception:
            pass
        if candidates is None or len(candidates) == 0:
            try:
                _safe_debug_log(u"[ingest] no candidates found by patterns/size")
            except Exception:
                pass
            return None
        # Choose the largest file as best candidate
        best = None
        best_size = -1
        try:
            _safe_debug_log(u"[ingest] candidates count: " + unicode(len(candidates)))
        except Exception:
            pass
        shown = 0
        for af in candidates:
            try:
                sz = af.getSize()
                if sz is not None and sz > best_size:
                    best = af
                    best_size = sz
                if shown < 5:
                    try:
                        _safe_debug_log(u"[ingest] candidate: {0} size={1}".format(af.getName(), sz))
                    except Exception:
                        pass
                    shown += 1
            except Exception:
                continue
        # As a last resort, if still none selected, pick the absolute largest file in the dataSource
        if best is None:
            try:
                _safe_debug_log(u"[ingest] best candidate is None after scan; falling back to absolute largest file")
            except Exception:
                pass
            try:
                largest = None
                largest_size = -1
                all_files = fm.findFiles(dataSource, "%", "%")
                if all_files is not None:
                    for f in all_files:
                        try:
                            s = f.getSize()
                            if s is not None and s > largest_size:
                                largest = f
                                largest_size = s
                        except Exception:
                            pass
                best = largest
                best_size = largest_size
            except Exception:
                pass
        if best is None:
            return None
        # Export under the case directory (ModuleOutput/Volatility3/tmp) and track for cleanup
        try:
            caseDir = Case.getCurrentCase().getCaseDirectory()
            baseOut = File(File(caseDir, "ModuleOutput"), "Volatility3")
            tmpDir = File(baseOut, "tmp")
            if not tmpDir.exists():
                tmpDir.mkdirs()
            fname = "vol3_image_" + unicode(System.currentTimeMillis()) + ".img"
            outFile = File(tmpDir, fname)
            _safe_debug_log(u"[ingest] exporting candidate: " + best.getName() + u" -> " + outFile.getAbsolutePath())
            if not self._export_abstract_file(best, outFile):
                return None
            try:
                self._temp_exports.append(outFile.getAbsolutePath())
            except Exception:
                pass
            return outFile.getAbsolutePath()
        except Exception as ex:
            self.logger.log(Level.WARNING, "Export of candidate image failed: " + unicode(ex))
            return None

    def _export_abstract_file(self, abstract_file, out_file):
        try:
            if AutopsyContentUtils is not None:
                AutopsyContentUtils.writeToFile(abstract_file, out_file)
                return True
        except Exception as ex:
            try:
                _safe_debug_log(u"[ingest] AutopsyContentUtils failed: " + unicode(ex))
            except Exception:
                pass
        in_stream = None
        out_stream = None
        try:
            in_stream = ReadContentInputStream(abstract_file)
            out_stream = BufferedOutputStream(FileOutputStream(out_file))
            if ApacheIOUtils is not None:
                ApacheIOUtils.copy(in_stream, out_stream)
            else:
                buf = _jbytes(8192, 'b')
                while True:
                    n = in_stream.read(buf)
                    if n == -1:
                        break
                    out_stream.write(buf, 0, n)
            out_stream.flush()
            return True
        except Exception as ex:
            try:
                _safe_debug_log(u"[ingest] Manual export failed: " + unicode(ex))
            except Exception:
                pass
            return False
        finally:
            try:
                if in_stream is not None:
                    in_stream.close()
            except Exception:
                pass
            try:
                if out_stream is not None:
                    out_stream.close()
            except Exception:
                pass

    def _sync_all_txt_to_fileset(self, dataSource):
        try:
            if self.txt_dir is None:
                return
            files = self.txt_dir.listFiles()
            if files is None:
                return
            for f in files:
                try:
                    n = f.getName()
                    if n is None or not n.lower().endswith(".txt"):
                        continue
                    plugin_guess = n[:-4]
                    # Skip if something with the same base already present (exact or with suffix _N)
                    try:
                        base = plugin_guess
                        if self._is_already_registered(dataSource, base + ".txt"):
                            try:
                                _safe_debug_log(u"[sync] already registered exact: " + base + ".txt")
                            except Exception:
                                pass
                            continue
                        # Loose check: any name starting with base + "_"
                        if self._is_already_registered(dataSource, base + "_"):
                            try:
                                _safe_debug_log(u"[sync] already registered with suffix: " + base + "_*")
                            except Exception:
                                pass
                            continue
                    except Exception:
                        pass
                    try:
                        _safe_debug_log(u"[sync] attempting register: " + f.getAbsolutePath())
                    except Exception:
                        pass
                    created = self._create_derived_file(dataSource, plugin_guess, f.getAbsolutePath())
                    if created is None:
                        # Direct local registration as a last resort
                        try:
                            _safe_debug_log(u"[sync] derived failed; fallback to addLocalFile for: " + f.getAbsolutePath())
                        except Exception:
                            pass
                        try:
                            self._register_local_txt(dataSource, f)
                        except Exception:
                            pass
                    else:
                        try:
                            _safe_debug_log(u"[sync] registered ok: " + created.getName())
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

    def _cleanup_temp_exports(self):
        try:
            if self._temp_exports is None:
                return
            for p in list(self._temp_exports):
                try:
                    f = File(p)
                    if f.exists():
                        try:
                            f.delete()
                        except Exception:
                            pass
                except Exception:
                    pass
            self._temp_exports = []
        except Exception:
            pass

    def _attach_outputs_as_data_source(self, original_ds):
        # Create a separate Local Files data source with all TXT outputs
        try:
            if self.txt_dir is None or not self.txt_dir.exists():
                return False
            files = self.txt_dir.listFiles()
            if files is None or len(files) == 0:
                return False
            path_list = ArrayList()
            file_list = ArrayList()
            count = 0
            for f in files:
                try:
                    if f is None or not f.exists():
                        continue
                    n = f.getName()
                    if n is None or not n.lower().endswith('.txt'):
                        continue
                    # Prefer non-empty files first
                    path_list.add(f.getAbsolutePath())
                    file_list.add(f)
                    count += 1
                except Exception:
                    pass
            if count == 0:
                return False
            caseObj = Case.getCurrentCase()
            ds_name = u"Volatility3 Output (" + (original_ds.getName() if original_ds is not None else u"DS") + u")"
            device_id = u"vol3-output-" + unicode(int(time.time()))
            tz = None
            try:
                # Some builds expose Case.getTimeZone()
                tz = caseObj.getTimeZone()
            except Exception:
                tz = "UTC"
            # Try common method signatures
            ds_created = False
            try:
                caseObj.addLocalFilesDataSource(path_list, tz, ds_name, device_id)
                ds_created = True
            except Exception:
                try:
                    _safe_debug_log(u"[attach-ds] addLocalFilesDataSource(List<String>) failed; trying List<File>")
                except Exception:
                    pass
                try:
                    caseObj.addLocalFilesDataSource(file_list, tz, ds_name, device_id)
                    ds_created = True
                except Exception:
                    try:
                        _safe_debug_log(u"[attach-ds] addLocalFilesDataSource(List<File>) failed; trying UTC string")
                    except Exception:
                        pass
                    try:
                        # Some versions take java.util.List and java.util.TimeZone; fall back to UTC string
                        caseObj.addLocalFilesDataSource(path_list, "UTC", ds_name, device_id)
                        ds_created = True
                    except Exception:
                        # Try alternative ordering (name, deviceId, list, tz)
                        try:
                            _safe_debug_log(u"[attach-ds] addLocalFilesDataSource(List,String) failed; trying alt ordering")
                        except Exception:
                            pass
                        try:
                            caseObj.addLocalFilesDataSource(ds_name, device_id, path_list, tz)
                            ds_created = True
                        except Exception:
                            try:
                                _safe_debug_log(u"[attach-ds] alt ordering with List<String> failed; trying List<File>")
                            except Exception:
                                pass
                            try:
                                caseObj.addLocalFilesDataSource(ds_name, device_id, file_list, tz)
                                ds_created = True
                            except Exception:
                                try:
                                    caseObj.addLocalFilesDataSource(ds_name, device_id, path_list, "UTC")
                                    ds_created = True
                                except Exception:
                                    try:
                                        _safe_debug_log(u"[attach-ds] all attempts to add Local Files DS failed")
                                    except Exception:
                                        pass
                                    ds_created = False
            if ds_created:
                try:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(IngestMessage.MessageType.INFO, MODULE_NAME,
                            u"Attached Volatility3 outputs as Local Files data source: " + ds_name))
                except Exception:
                    pass
                return True
        except Exception:
            pass
        return False

    def _register_local_txt(self, dataSource, file_obj):
        # Adds a TXT directly as LocalFile under the data source
        try:
            if file_obj is None:
                return None
            name = file_obj.getName()
            size = file_obj.length()
            ts = long(file_obj.lastModified() / 1000) if file_obj.lastModified() > 0 else 0
            path = file_obj.getAbsolutePath()
            sk = Case.getCurrentCase().getSleuthkitCase()
            # Prefer to place under the 'Volatility3' directory for this data source
            try:
                parent = self._get_or_create_vol_dir(dataSource)
            except Exception:
                parent = dataSource
            for i in range(0, 5):
                candidate = name if i == 0 else (name[:-4] + "_" + str(i) + ".txt")
                try:
                    lf = self._add_local_file_robust(sk, parent, candidate, size, ts, path, "text/plain")
                    if lf is not None:
                        try:
                            _safe_debug_log(u"[local] register fallback addLocalFile: " + lf.getName())
                        except Exception:
                            pass
                        return lf
                except Exception as ex:
                    try:
                        _safe_debug_log(u"[local] register fallback addLocalFile error (attempt {0}): ".format(i) + unicode(ex))
                    except Exception:
                        pass
                    continue
        except Exception:
            pass
        return None

    def postProcess(self, progressBar):
        try:
            if self.report_root_dir is None or not self.report_root_dir.exists():
                return
            index_file = File(self.report_root_dir, "Volatility3_report.html")
            bw = BufferedWriter(OutputStreamWriter(FileOutputStream(index_file), "UTF-8"))
            try:
                bw.write("<html><head><meta charset='utf-8'><title>Volatility 3 Report</title></head><body>")
                bw.write("<h1>Volatility 3 Report</h1>")
                txt_dir = File(self.report_root_dir, "txt")
                if txt_dir.exists():
                    bw.write("<h2>TXT outputs</h2><ul>")
                    files = txt_dir.listFiles()
                    if files is not None:
                        for f in files:
                            try:
                                name = f.getName()
                                href = f.toURI().toString()
                                bw.write("<li><a href='" + href + "'>" + name + "</a> (" + str(f.length()) + " bytes)</li>")
                            except Exception:
                                pass
                    bw.write("</ul>")
                json_dir = File(self.report_root_dir, "json")
                if json_dir.exists():
                    bw.write("<h2>JSONL outputs</h2><ul>")
                    files = json_dir.listFiles()
                    if files is not None:
                        for f in files:
                            try:
                                name = f.getName()
                                href = f.toURI().toString()
                                bw.write("<li><a href='" + href + "'>" + name + "</a> (" + str(f.length()) + " bytes)</li>")
                            except Exception:
                                pass
                    bw.write("</ul>")
                logs_dir = File(self.report_root_dir, "logs")
                if logs_dir.exists():
                    bw.write("<h2>Logs</h2><ul>")
                    files = logs_dir.listFiles()
                    if files is not None:
                        for f in files:
                            try:
                                name = f.getName()
                                href = f.toURI().toString()
                                bw.write("<li><a href='" + href + "'>" + name + "</a> (" + str(f.length()) + " bytes)</li>")
                            except Exception:
                                pass
                    bw.write("</ul>")
                bw.write("</body></html>")
                bw.flush()
            finally:
                try:
                    bw.close()
                except Exception:
                    pass
            Case.getCurrentCase().addReport(index_file.getAbsolutePath(), MODULE_NAME, "Volatility 3 Report")
        except Exception as ex:
            try:
                self.logger.log(Level.WARNING, "Failed to build/register report index: " + unicode(ex))
            except Exception:
                pass

    def _bb_type_tool_output(self):
        try:
            return BlackboardArtifact.Type.TSK_TOOL_OUTPUT
        except Exception:
            try:
                return BlackboardArtifact.ARTIFACT_TYPE.TSK_TOOL_OUTPUT
            except Exception:
                try:
                    return BlackboardArtifact.Type.TSK_INTERESTING_ITEM
                except Exception:
                    return None

    def _bb_attr(self, name):
        try:
            return getattr(BlackboardAttribute.Type, name)
        except Exception:
            try:
                return getattr(BlackboardAttribute.ATTRIBUTE_TYPE, name)
            except Exception:
                return None

    def _count_lines(self, file_path):
        try:
            f = File(file_path)
            if not f.exists():
                return 0
            br = BufferedReader(InputStreamReader(FileInputStream(f), "UTF-8"))
            try:
                c = 0
                while True:
                    line = br.readLine()
                    if line is None:
                        break
                    if len(line.strip()) > 0:
                        c += 1
                return c
            finally:
                try:
                    br.close()
                except Exception:
                    pass
        except Exception:
            return 0

    def _create_derived_file(self, dataSource, plugin_name, src_path):
        try:
            if src_path is None:
                return None
            src = File(src_path)
            if not src.exists():
                return None
            # Ensure/locate a 'Volatility3' directory under the data source to attach files (cached)
            parent = self._get_or_create_vol_dir(dataSource)
            try:
                _safe_debug_log(u"[derived] parent for DS '{0}': {1}".format(dataSource.getName(), parent.getName() if parent is not None else u"<none>"))
            except Exception:
                pass
            # Use the full sanitized plugin name to keep names unique and consistent
            # e.g., windows.pslist -> windows.pslist.txt (avoids collisions across plugins)
            try:
                base = self._sanitize_plugin_name(plugin_name)
            except Exception:
                base = plugin_name.replace("/", "_").replace("\\", "_")
            fileName = base + ".txt"
            # Copy TXT into CaseDirectory/DerivedFiles/Volatility3 so Autopsy can read it reliably
            caseDir = Case.getCurrentCase().getCaseDirectory()
            destDir = File(File(caseDir, "DerivedFiles"), "Volatility3")
            if not destDir.exists():
                destDir.mkdirs()
            destFile = File(destDir, fileName)
            idx = 0
            while destFile.exists() and idx < 100:
                idx += 1
                # Use base_#.txt to ensure uniqueness across runs
                destFile = File(destDir, base + "_" + str(idx) + ".txt")
            # Initialize streams and copy file into DerivedFiles/Volatility3
            inSt = None
            outSt = None
            try:
                inSt = FileInputStream(src)
                outSt = FileOutputStream(destFile)
                if ApacheIOUtils is not None:
                    ApacheIOUtils.copy(inSt, outSt)
                else:
                    buf = _jbytes(8192, 'b')
                    while True:
                        n = inSt.read(buf)
                        if n == -1:
                            break
                        outSt.write(buf, 0, n)
                outSt.flush()
            except Exception as e:
                try:
                    self.logger.log(Level.WARNING, "Failed to copy TXT to DerivedFiles: {0}".format(unicode(e)))
                except Exception:
                    pass
            finally:
                try:
                    if outSt is not None:
                        outSt.close()
                except Exception:
                    pass
                try:
                    if inSt is not None:
                        inSt.close()
                except Exception:
                    pass
            size = destFile.length()
            ts = long(destFile.lastModified() / 1000) if destFile.lastModified() > 0 else 0
            # If configured to register as LocalFile only, do it now for guaranteed visibility
            try:
                if getattr(self, 'register_mode', 'derived') == 'local':
                    try:
                        lf = self._register_local_txt(dataSource, destFile)
                        if lf is not None:
                            return lf
                    except Exception:
                        pass
                    # If local registration failed, fall through to legacy derived path
            except Exception:
                pass
            sk = Case.getCurrentCase().getSleuthkitCase()
            details = u"Volatility plugin: " + plugin_name
            localPathAbs = destFile.getAbsolutePath()
            # For addDerivedFile, Autopsy 4.21 expects a path relative to the case directory.
            # Build a safe relative path like "DerivedFiles/Volatility3/name.txt".
            try:
                caseDirFile = File(caseDir)
                relUri = caseDirFile.toURI().relativize(destFile.toURI())
                localPathRel = relUri.getPath()
                if localPathRel is None or len(localPathRel) == 0:
                    localPathRel = destFile.getName()
            except Exception:
                localPathRel = destFile.getName()
            # Also compute a relative path to the original ModuleOutput TXT, so we can
            # fallback to referencing it directly if registering the copied file fails.
            srcLocalRel = None
            try:
                srcFile = File(src_path)
                caseDirFile = File(caseDir)
                relUri2 = caseDirFile.toURI().relativize(srcFile.toURI())
                srcLocalRel = relUri2.getPath()
            except Exception:
                srcLocalRel = None
            try:
                _safe_debug_log(u"[derived] prepared file: {0} (size={1})".format(localPathAbs, size))
            except Exception:
                pass
            # Register strictly as a derived file that references the on-disk copy
            # under CaseDirectory/DerivedFiles/Volatility3 so entries appear in File Views.
            derived = None
            for attempt in range(0, 3):
                candidate = destFile.getName() if attempt == 0 else (base + "_" + str(attempt) + ".txt")
                try:
                    derived = sk.addDerivedFile(candidate, localPathRel, size,
                                                ts, ts, ts, ts, True, parent,
                                                details, MODULE_NAME, MODULE_VERSION, "",
                                                TskData.TSK_FS_NAME_TYPE_ENUM.REG, TskData.TSK_FS_META_TYPE_ENUM.REG,
                                                None, 0, None, SleuthkitCase.EncodingType.NONE)
                    if derived is not None:
                        try:
                            _safe_debug_log(u"[derived] addDerivedFile registered: " + derived.getName())
                        except Exception:
                            pass
                            break
                except Exception as ex:
                    try:
                        _safe_debug_log(u"[derived] addDerivedFile (enums) error (attempt {0}): ".format(attempt) + unicode(ex))
                    except Exception:
                        pass
                    try:
                        derived = sk.addDerivedFile(candidate, localPathRel, size,
                                                    ts, ts, ts, ts, True, parent,
                                                    details, MODULE_NAME, MODULE_VERSION, "")
                        if derived is not None:
                            try:
                                _safe_debug_log(u"[derived] addDerivedFile (legacy) registered: " + derived.getName())
                            except Exception:
                                pass
                            break
                    except Exception as ex2:
                        try:
                            _safe_debug_log(u"[derived] addDerivedFile (legacy) error (attempt {0}): ".format(attempt) + unicode(ex2))
                        except Exception:
                            pass
                        derived = None
            # Fallback: if registering the copy failed, try registering the ModuleOutput TXT directly
            if derived is None and srcLocalRel is not None:
                try:
                    _safe_debug_log(u"[derived] primary registration failed, trying ModuleOutput path: " + srcLocalRel)
                except Exception:
                    pass
                for attempt in range(0, 3):
                    candidate = destFile.getName() if attempt == 0 else (base + "_" + str(attempt) + ".txt")
                    try:
                        derived = sk.addDerivedFile(candidate, srcLocalRel, File(src_path).length(),
                                                    ts, ts, ts, ts, True, parent,
                                                    details, MODULE_NAME, MODULE_VERSION, "",
                                                    TskData.TSK_FS_NAME_TYPE_ENUM.REG, TskData.TSK_FS_META_TYPE_ENUM.REG,
                                                    None, 0, None, SleuthkitCase.EncodingType.NONE)
                        if derived is not None:
                            try:
                                _safe_debug_log(u"[derived] addDerivedFile (src path) registered: " + derived.getName())
                            except Exception:
                                pass
                            break
                    except Exception as ex3:
                        try:
                            _safe_debug_log(u"[derived] addDerivedFile (src path, enums) error (attempt {0}): ".format(attempt) + unicode(ex3))
                        except Exception:
                            pass
                        try:
                            derived = sk.addDerivedFile(candidate, srcLocalRel, File(src_path).length(),
                                                        ts, ts, ts, ts, True, parent,
                                                        details, MODULE_NAME, MODULE_VERSION, "")
                            if derived is not None:
                                try:
                                    _safe_debug_log(u"[derived] addDerivedFile (src path, legacy) registered: " + derived.getName())
                                except Exception:
                                    pass
                                break
                        except Exception as ex4:
                            try:
                                _safe_debug_log(u"[derived] addDerivedFile (src path, legacy) error (attempt {0}): ".format(attempt) + unicode(ex4))
                            except Exception:
                                pass
                            derived = None
            # Last-chance: register as LocalFile so it at least appears under File Views
            if derived is None:
                try:
                    _safe_debug_log(u"[derived] derived registration failed; trying addLocalFile")
                except Exception:
                    pass
                try:
                    lf = self._add_local_file_robust(sk, parent, destFile.getName(), size, ts,
                                                     localPathAbs, "text/plain")
                    if lf is not None:
                        try:
                            _safe_debug_log(u"[derived] addLocalFile(copy) registered: " + lf.getName())
                        except Exception:
                            pass
                        return lf
                except Exception as ex5:
                    try:
                        _safe_debug_log(u"[derived] addLocalFile(copy) error: " + unicode(ex5))
                    except Exception:
                        pass
                    try:
                        # If copy didn't succeed, point to source ModuleOutput file directly
                        srcAbs = File(src_path).getAbsolutePath()
                        lf = self._add_local_file_robust(sk, parent, destFile.getName(), File(src_path).length(), ts,
                                                         srcAbs, "text/plain")
                        if lf is not None:
                            try:
                                _safe_debug_log(u"[derived] addLocalFile(src) registered: " + lf.getName())
                            except Exception:
                                pass
                            return lf
                    except Exception as ex6:
                        try:
                            _safe_debug_log(u"[derived] addLocalFile(src) error: " + unicode(ex6))
                        except Exception:
                            pass
                        pass
            else:
                # Verify presence in File Views under DS; if not clear, attempt LocalFile fallback
                try:
                    fm = Case.getCurrentCase().getServices().getFileManager()
                    present = False
                    try:
                        # Broader query, then inspect parent path to confirm it resides under a Volatility3 dir
                        foundX = fm.findFiles(dataSource, derived.getName(), "%")
                        if foundX is not None:
                            it = foundX
                            # Support both Python list and Java List
                            try:
                                iterable = it if hasattr(it, '__iter__') else [it]
                            except Exception:
                                iterable = [it]
                            for af in iterable:
                                try:
                                    p = af.getParentPath()
                                    # Parent path can be '/Volatility3' or contain it; do a case-insensitive check
                                    if p is not None and u"volatility3" in p.lower():
                                        present = True
                                        break
                                except Exception:
                                    continue
                    except Exception:
                        present = False
                    if not present:
                        try:
                            _safe_debug_log(u"[verify] Not visible under Volatility3; adding LocalFile copy: " + derived.getName())
                        except Exception:
                            pass
                        try:
                            lf = self._add_local_file_robust(sk, parent, derived.getName(), size, ts, localPathAbs, "text/plain")
                            if lf is not None:
                                try:
                                    _safe_debug_log(u"[verify] LocalFile(copy) registered: " + lf.getName())
                                except Exception:
                                    pass
                                return lf
                        except Exception:
                            pass
                except Exception:
                    pass
                # If mode is 'both', also add an explicit LocalFile entry, using a safe suffix to avoid collision
                try:
                    if getattr(self, 'register_mode', 'derived') == 'both':
                        try:
                            base_only = destFile.getName()
                            # Try a few deterministic alternate names
                            alt_names = [base_only, base + u"_local.txt", base + u"_copy.txt", base + u"_view.txt"]
                            for nm in alt_names:
                                try:
                                    lf = self._add_local_file_robust(sk, parent, nm, size, ts, localPathAbs, "text/plain")
                                    if lf is not None:
                                        try:
                                            _safe_debug_log(u"[both] Added LocalFile alongside Derived: " + lf.getName())
                                        except Exception:
                                            pass
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            pass
                except Exception:
                    pass
            return derived
        except Exception:
            return None

    

    def _post_txt_artifact(self, parentContent, plugin_name, txt_path, json_count, ok, timeout_flag):
        try:
            bb_type = self._bb_type_tool_output()
            if bb_type is None:
                return
            art = parentContent.newArtifact(bb_type)
            status = 'success' if ok and not timeout_flag else ('timeout' if timeout_flag else 'issues')
            attrs = []
            a_prog = self._bb_attr('TSK_PROG_NAME')
            if a_prog is not None:
                attrs.append(BlackboardAttribute(a_prog, MODULE_NAME, 'Volatility 3'))
            a_set = self._bb_attr('TSK_SET_NAME')
            if a_set is not None:
                attrs.append(BlackboardAttribute(a_set, MODULE_NAME, plugin_name))
            a_comment = self._bb_attr('TSK_COMMENT')
            if a_comment is not None:
                attrs.append(BlackboardAttribute(a_comment, MODULE_NAME, 'records: {0}; status: {1}'.format(json_count, status)))
            a_path = self._bb_attr('TSK_PATH') or self._bb_attr('TSK_FILE_PATH')
            if a_path is not None and txt_path is not None:
                attrs.append(BlackboardAttribute(a_path, MODULE_NAME, txt_path))
            # Embed a short text preview so results are readable from Analysis Results
            try:
                preview_attr = self._bb_attr('TSK_TEXT')
                if preview_attr is None:
                    preview_attr = self._bb_attr('TSK_DESCRIPTION')
                if preview_attr is not None and txt_path is not None:
                    # Read up to 100 KB to avoid oversized artifacts
                    sample = self._read_text(txt_path)
                    if sample is not None and len(sample) > 0:
                        if len(sample) > 100 * 1024:
                            sample = sample[:100 * 1024] + u"\n... (truncated)"
                        attrs.append(BlackboardAttribute(preview_attr, MODULE_NAME, sample))
            except Exception:
                pass
            for a in attrs:
                try:
                    art.addAttribute(a)
                except Exception:
                    pass
            try:
                bb = Case.getCurrentCase().getServices().getBlackboard()
                try:
                    bb.postArtifact(art, MODULE_NAME)
                except Exception:
                    try:
                        bb.indexArtifact(art)
                    except Exception:
                        pass
            except Exception:
                pass
        except Exception:
            pass

    def shutDown(self):
        self.logger.log(Level.INFO, "Volatility 3 ingest module shutdown")
        try:
            self._cleanup_temp_exports()
        except Exception:
            pass

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
    def _get_or_create_vol_dir(self, dataSource):
        # Returns a stable 'Volatility3' directory under the given data source.
        # Caches by data source id to avoid creating duplicates.
        try:
            # Reuse same object within one process() invocation
            try:
                if self._current_vol_dir is not None:
                    return self._current_vol_dir
            except Exception:
                pass
            ds_id = None
            try:
                ds_id = dataSource.getId()
            except Exception:
                ds_id = None
            if ds_id is not None and ds_id in self._vol_dir_cache:
                self._current_vol_dir = self._vol_dir_cache[ds_id]
                return self._current_vol_dir
            # Find existing directory named 'Volatility3'
            try:
                fm = Case.getCurrentCase().getServices().getFileManager()
                # Look up by directory name
                found = fm.findFiles(dataSource, "Volatility3", "%")
                if found is not None:
                    for af in found:
                        try:
                            if af.isDir() and af.getName() == "Volatility3":
                                if ds_id is not None:
                                    self._vol_dir_cache[ds_id] = af
                                self._current_vol_dir = af
                                return self._current_vol_dir
                        except Exception:
                            pass
            except Exception:
                pass
            # Prefer a real derived directory first (shows reliably under File Views)
            sk = Case.getCurrentCase().getSleuthkitCase()
            # Fallbacks: derived DIR (new enums, then legacy)
            try:
                ts = long(System.currentTimeMillis() / 1000)
                d = sk.addDerivedFile("Volatility3", "", 0,
                                       ts, ts, ts, ts, False, dataSource,
                                       u"Volatility 3 output root", MODULE_NAME, MODULE_VERSION, "",
                                       TskData.TSK_FS_NAME_TYPE_ENUM.DIR, TskData.TSK_FS_META_TYPE_ENUM.DIR,
                                       None, 0, None, SleuthkitCase.EncodingType.NONE)
                if d is not None:
                    if ds_id is not None:
                        self._vol_dir_cache[ds_id] = d
                    self._current_vol_dir = d
                    return self._current_vol_dir
            except Exception:
                try:
                    d = sk.addDerivedFile("Volatility3", "", 0,
                                           ts, ts, ts, ts, False, dataSource,
                                           u"Volatility 3 output root", MODULE_NAME, MODULE_VERSION, "")
                    if d is not None:
                        if ds_id is not None:
                            self._vol_dir_cache[ds_id] = d
                        self._current_vol_dir = d
                        return self._current_vol_dir
                except Exception:
                    pass
            # Last resort: virtual directory
            try:
                d = sk.addVirtualDirectory("Volatility3", dataSource)
                if d is not None:
                    if ds_id is not None:
                        self._vol_dir_cache[ds_id] = d
                    self._current_vol_dir = d
                    return self._current_vol_dir
            except Exception:
                pass
        except Exception:
            pass
        return dataSource

    def _ensure_vol3_dir(self, dataSource):
        # Ensure (or create) a visible directory named 'Volatility3' under the data source.
        try:
            fm = Case.getCurrentCase().getServices().getFileManager()
            try:
                # Look up by directory name
                found = fm.findFiles(dataSource, "Volatility3", "%")
                if found is not None:
                    for af in found:
                        try:
                            if af.isDir() and af.getName() == "Volatility3":
                                return af
                        except Exception:
                            continue
            except Exception:
                pass
            # Not found; create a directory node via addDerivedFile (DIR)
            sk = Case.getCurrentCase().getSleuthkitCase()
            ts = long(System.currentTimeMillis() / 1000)
            try:
                d = sk.addDerivedFile("Volatility3", "", 0,
                                      ts, ts, ts, ts, False, dataSource,
                                      u"Volatility 3 output root", MODULE_NAME, MODULE_VERSION, "",
                                      TskData.TSK_FS_NAME_TYPE_ENUM.DIR, TskData.TSK_FS_META_TYPE_ENUM.DIR,
                                      None, 0, None, SleuthkitCase.EncodingType.NONE)
                if d is not None:
                    return d
            except Exception:
                try:
                    # Older signature without enums
                    d = sk.addDerivedFile("Volatility3", "", 0,
                                          ts, ts, ts, ts, False, dataSource,
                                          u"Volatility 3 output root", MODULE_NAME, MODULE_VERSION, "")
                    if d is not None:
                        return d
                except Exception:
                    pass
        except Exception:
            pass
        return dataSource

    def _is_already_registered(self, dataSource, name):
        try:
            fm = Case.getCurrentCase().getServices().getFileManager()
            # Support a simple "prefix" check if caller passes a name ending with '_'
            # (used by sync logic to skip items like base_1.txt, base_2.txt, ...)
            if name is not None and name.endswith('_'):
                prefix = name
                try:
                    found_all = fm.findFiles(dataSource, "%", "Volatility3")
                except Exception:
                    found_all = None
                if found_all is None:
                    return False
                try:
                    for af in found_all:
                        try:
                            n = af.getName()
                            if n is not None and n.startswith(prefix) and n.lower().endswith('.txt'):
                                return True
                        except Exception:
                            continue
                except Exception:
                    return False
                return False

            # Exact filename check under Volatility3 directory
            try:
                found = fm.findFiles(dataSource, name, "Volatility3")
            except Exception:
                found = None
            if found is None:
                return False
            try:
                # Java list supports size(); len() also works in Jython
                return (len(found) > 0)
            except Exception:
                try:
                    return (found.size() > 0)
                except Exception:
                    # If we can't determine size, assume not present to avoid false skips
                    return False
        except Exception:
            return False

    def _detect_operating_system(self, dump_path):
        for entry in OS_DETECTION_SEQUENCE:
            self.logger.log(Level.INFO, "OS detection attempt using {0}".format(entry[1]))
            try:
                _safe_debug_log(u"[detect] Trying: {0}".format(entry[1]))
            except Exception:
                pass
            os_key, plugin_name, renderer = entry
            result = self.runner.run_detection(dump_path, plugin_name, renderer, min(120, self.timeout_sec), self._is_cancelled)
            if result.error is not None:
                self.logger.log(Level.WARNING, "Detection {0} error: {1}".format(plugin_name, result.error))
                try:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(_msg_type_warning(), MODULE_NAME,
                                                    "OS detection error in {0}: {1}".format(plugin_name, unicode(result.error))))
                except Exception:
                    pass
                try:
                    _safe_debug_log(u"[detect] Error: " + unicode(result.error))
                except Exception:
                    pass
            else:
                self.logger.log(Level.INFO, "Detection {0} exit code: {1}".format(plugin_name, result.exit_code))
                try:
                    _safe_debug_log(u"[detect] Exit code: {0}".format(result.exit_code))
                except Exception:
                    pass
            if result.cancelled:
                return None
            if result.timed_out:
                self.logger.log(Level.WARNING, "Detection plugin timed out: " + plugin_name)
                try:
                    IngestServices.getInstance().postMessage(
                        IngestMessage.createMessage(_msg_type_warning(), MODULE_NAME,
                                                    "OS detection timed out: " + plugin_name))
                except Exception:
                    pass
                try:
                    _safe_debug_log(u"[detect] Timed out: " + plugin_name)
                except Exception:
                    pass
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

    def _build_extra_opts(self):
        opts = []
        # Debug verbosity: add -v repeated N times
        try:
            verbosity = self.config.get_int("debug", "verbosity", 0)
        except Exception:
            verbosity = 0
        if verbosity is not None and verbosity > 0:
            count = max(0, min(int(verbosity), 5))
            for i in range(count):
                opts.append(u"-v")
        # Plugin and symbol directories (semicolon separated as per vol3)
        try:
            plugin_dirs = self.config.get_list("runtime", "plugin_dirs")
        except Exception:
            plugin_dirs = []
        if plugin_dirs is not None and len(plugin_dirs) > 0:
            opts.extend([u"-p", u";".join(plugin_dirs)])
        try:
            symbol_dirs = self.config.get_list("runtime", "symbol_dirs")
        except Exception:
            symbol_dirs = []
        if symbol_dirs is not None and len(symbol_dirs) > 0:
            opts.extend([u"-s", u";".join(symbol_dirs)])
        # Cache path
        cache_path = None
        try:
            cache_path = self.config.get("runtime", "cache_path", "")
        except Exception:
            cache_path = ""
        if cache_path is not None and len(cache_path.strip()) > 0:
            opts.extend([u"--cache-path", cache_path.strip()])
        # Offline / remote ISF URL
        offline = False
        try:
            offline_value = self.config.get("runtime", "offline", "")
            if offline_value is not None and len(offline_value) > 0:
                val = offline_value.strip().lower()
                offline = val in ("1", "true", "yes", "on")
        except Exception:
            offline = False
        if offline:
            opts.append(u"--offline")
        else:
            try:
                remote_url = self.config.get("runtime", "remote_isf_url", "")
            except Exception:
                remote_url = ""
            if remote_url is not None and len(remote_url.strip()) > 0:
                opts.extend([u"-u", remote_url.strip()])
        return opts

    def _write_run_diagnostics(self, append_after_detection):
        # Writes basic diagnostics to logs/diagnostics.txt
        try:
            path = File(self.logs_dir, "diagnostics.txt").getAbsolutePath()
            writer = BufferedWriter(OutputStreamWriter(FileOutputStream(File(path), True), "UTF-8"))
            try:
                if not append_after_detection:
                    writer.write("Python: {0}\n".format(self.python_exe))
                    writer.write("Volatility: {0}\n".format(self.vol_exe))
                    writer.write("Timeout per plugin: {0}\n".format(self.timeout_sec))
                    writer.write("Max stdout bytes: {0}\n".format(self.max_stdout_bytes))
                    try:
                        from java.lang import System as JSystem
                        env_path = JSystem.getenv("PATH")
                        if env_path is not None:
                            writer.write("PATH: {0}\n".format(env_path))
                    except Exception:
                        pass
                else:
                    detected = self.last_detected_os if self.last_detected_os is not None else "unknown"
                    writer.write("Detected OS: {0}\n".format(detected))
                writer.flush()
            finally:
                try:
                    writer.close()
                except Exception:
                    pass
        except Exception:
            pass

    def _read_text(self, file_path):
        file_obj = File(file_path)
        if not file_obj.exists():
            return ""
        reader = None
        try:
            reader = BufferedReader(InputStreamReader(FileInputStream(file_obj), "UTF-8"))
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

    def _record_error(self, plugin_name, renderer, stderr_tmp_path, exec_result):
        try:
            if stderr_tmp_path is None:
                return
            # Read stderr temp content
            content = self._read_text(stderr_tmp_path)
            messages = []
            if exec_result is not None:
                if exec_result.cancelled:
                    messages.append("Cancelled by user/job")
                if exec_result.timed_out:
                    messages.append("Timed out")
                if exec_result.exit_code != 0:
                    messages.append("Exit code: {0}".format(exec_result.exit_code))
                if exec_result.error is not None and len(exec_result.error) > 0:
                    messages.append("Exec error: {0}".format(exec_result.error))
            lower = content.lower() if content is not None else ""
            # Common Vol3 issues
            if "unable to validate the plugin requirements" in lower:
                messages.append("Unable to validate plugin requirements (likely missing symbols)")
            if "symbol file could not be downloaded" in lower or "pdbutil" in lower:
                messages.append("Symbol download failed (check network/URL or use offline symbols)")
            if "no suitable translation layer" in lower:
                messages.append("No suitable translation layer (check image format/-f)")
            if "run 'vol.py <plugin> --help'" in lower:
                messages.append("See plugin help for required options")
            # If there is no content and exit was ok, do not report
            if len(messages) == 0 and (content is None or len(content.strip()) == 0):
                return
            # Append summary file
            summary = File(self.errors_summary_path)
            parent = summary.getParentFile()
            if parent is not None and not parent.exists():
                parent.mkdirs()
            writer = None
            try:
                writer = BufferedWriter(OutputStreamWriter(FileOutputStream(summary, True), "UTF-8"))
                writer.write("[{0}::{1}]\n".format(plugin_name, renderer))
                if len(messages) > 0:
                    for msg in messages:
                        writer.write("- {0}\n".format(msg))
                # Write first few lines of stderr for context (max 5)
                if content is not None and len(content.strip()) > 0:
                    lines = content.split("\n")
                    limit = min(5, len(lines))
                    for i in range(limit):
                        writer.write(lines[i] + "\n")
                writer.write("\n")
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass
            # Post an ingest message to surface the issue in UI with proper severity
            try:
                short = "; ".join(messages) if len(messages) > 0 else "See logs for details"
                severity = _msg_type_info()
                if exec_result is not None:
                    try:
                        if exec_result.error is not None and len(unicode(exec_result.error)) > 0:
                            severity = _msg_type_error()
                        elif exec_result.timed_out:
                            severity = _msg_type_warning()
                        elif exec_result.exit_code is not None and exec_result.exit_code != 0:
                            severity = _msg_type_warning()
                    except Exception:
                        pass
                IngestServices.getInstance().postMessage(
                    IngestMessage.createMessage(severity, MODULE_NAME,
                                                "Issue in {0} ({1}): {2}".format(plugin_name, renderer, short)))
            except Exception:
                pass
        except Exception:
            pass

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
        try:
            _safe_debug_log("[factory] Initialized Vol3IngestModuleFactory")
        except Exception:
            pass

    def isDataSourceIngestModuleFactory(self):
        return True

    def getModuleDisplayName(self):
        return MODULE_NAME

    def getModuleDescription(self):
        return "Runs Volatility 3 as an external process and records findings."

    def getModuleVersionNumber(self):
        return MODULE_VERSION

    def hasIngestJobSettingsPanel(self):
        return True

    def getDefaultIngestJobSettings(self):
        try:
            _safe_debug_log("[factory] getDefaultIngestJobSettings")
        except Exception:
            pass
        return Vol3JobSettings()

    def getIngestJobSettingsPanel(self, settings):
        try:
            if settings is None:
                settings = Vol3JobSettings()
            module_dir = _module_directory()
            config_path = os.path.join(module_dir, "resources", "config.ini")
            _safe_debug_log(u"[factory] getIngestJobSettingsPanel; config={0}".format(config_path))
            config = Vol3Config(config_path, self.logger)
            config.load()
            panel = Vol3SettingsPanel(settings, config, self.logger)
            _safe_debug_log("[factory] Settings panel constructed")
            return panel
        except Exception as ex:
            try:
                _safe_debug_log(u"[factory] Error building settings panel: " + unicode(ex))
            except Exception:
                pass
            raise ex

    def createDataSourceIngestModule(self, settings):
        try:
            _safe_debug_log("[factory] createDataSourceIngestModule invoked")
        except Exception:
            pass
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
                    except Exception as ex:
                        try:
                            _safe_debug_log(u"[factory] Settings deserialize error: " + unicode(ex))
                        except Exception:
                            pass
                settings = new_settings
            else:
                settings = Vol3JobSettings()
        module = Vol3DataSourceIngestModule(settings)
        try:
            _safe_debug_log("[factory] DataSourceIngestModule constructed")
        except Exception:
            pass
        return module






