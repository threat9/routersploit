import json
import os
import platform
import sys
import threading
import traceback
from copy import deepcopy
from datetime import datetime
from string import lower
    
class AbstractLog(object):
#   AbstractLog provides an ABC for the creation of a concrete Log class
    def __init__(self, ToolProjectName, ToolProjectVersion, ToolName=None, ToolVersion=None, options={}, params={}):
        
        # setup default options, deepcopy those passed by user, set missing with defaults, if any errors use defaults 
        def_opts = {'OutputDir': 'D:\\DSZOPSDisk\\logs',
                    'Prefix': 'concernedparent',
                    'Logging': True,
                    'Verbose': True,
                    'Debugging': True,
                    }
        try:
            self.options = deepcopy(options)
            for k in def_opts:
                if not self.options.has_key(k):
                    self.options[k] = def_opts[k]
        except:
            self.options = def_opts
            self.notifyOfError('{options} passed were invalid and have been reset.  Moving on.')            
        
        # setup default params, deepcopy those passed by user, set missing with defaults, if any errors use defaults
        try:
            def_pars = {'ToolProjectName': ToolProjectName,
                        'ToolProjectVersion': ToolProjectVersion,
                        'ToolName': ToolName if ToolName else ToolProjectName,
                        'ToolVersion': ToolVersion if ToolVersion else ToolProjectVersion,
                        'EventType': 'event',
                        }
        except:
            def_pars = {'ToolProjectName': 'Unknown', 'EventType': 'event'}
            self.notifyOfError('A parameter passed was invalid.  ToolProjectName set to Unknown.  Moving on.')
        try:
            self.params = deepcopy(params)
            for k in def_pars:
                if not self.params.has_key(k):
                    self.params[k] = def_pars[k]
        except:
            self.params = def_pars
            self.notifyOfError('{params} passed were invalid and have been reset.  Moving on.')

        # dispatcher will scavenge files deeper than specified path
        # for the foreseeable future expect root of path to be D:\DSZOPSDisk
        # by default we will try D:\DSZOPSDisk\logs and if that fails try cwd
        try:
            self.options['OutputDir'] = os.path.join(self.options['OutputDir'], self.options['Prefix'])
            if not os.path.exists(self.options['OutputDir']):
                os.mkdir(self.options['OutputDir'])
        except:
            try:
                self.options['OutputDir'] = os.path.join(os.getcwd(), self.options['Prefix'])
                if not os.path.exists(self.options['OutputDir']):
                    os.mkdir(self.options['OutputDir'])
            except:
                self.notifyOfError('Could not open a log output directory.  Logging will be disabled.')
                self.options['Logging'] = False
        finally:
            if self.options['Verbose'] and self.options['Logging']: print "Logging to " + self.options['OutputDir']
        
    def __call__(self, ToolEvent='pulsed', ToolName=None, ToolVersion=None, Annotation=None, ToolStatus='notify', ToolProjectName=None, ToolProjectVersion=None, CommandLine=None, params={}):
        try:
            d = deepcopy(self.params)
            for k in params:
                d[k] = deepcopy(params[k])
            d['ToolEvent'] = ToolEvent 
            d['ToolStatus'] = ToolStatus
            if d.has_key('StartTime'): d['EventTime'] = d['StartTime']
            else: d['EventTime'] = datetime.now()
            if ToolProjectName: d['ToolProjectName'] = ToolProjectName
            if ToolProjectVersion: d['ToolProjectVersion'] = ToolProjectVersion
            if ToolName: d['ToolName'] = ToolName
            if ToolVersion: d['ToolVersion'] = ToolVersion
            if Annotation: d['Annotation'] = Annotation
            if CommandLine: d['CommandLine'] = CommandLine
            self.fromDICTwriteJSON(d)
        except:
            self.notifyOfError("Failed to generate output file.  Parameters were:\n"+str(params))
    
    def __getattr__(self,name):
        return object.__getattribute__(self,lower(name))
    
    def __setattr__(self,name,value):
        object.__setattr__(self, lower(name), value)
        if isinstance(self.__getattr__(lower(name)), self.AbstractLogType):
            self.__getattr__(name).log = self
            self.__getattr__(name).name = lower(name)
            
    def __getitem__(self,key):
        return self.__getattr__(key)
    
    def __setitem__(self,key,value):
        self.__setattr__(key, value)
        
    def open(self): self('opened')
    
    def close(self):
        self.running = False
        self('closed')
    
    def pacemaker(self, timeout=60):
    #   This is a stand-alone heartbeat generator.  To pulse from your own control loop,
    #   call your AbstractLog subclass instance event handler (e.g. AbstractLog['event']()
        def __target(timeout=60):
            if platform.uname()[0].lower() == "windows":
                import win32con
                import win32event
                self.running = True
                kill = win32event.CreateEvent(None, 1, 0, None)
                pulse = win32event.CreateWaitableTimer(None, 0, None)
                win32event.SetWaitableTimer(pulse, 0, timeout*1000, None, None, False)
                while(self.running):
                    try:
                        result = win32event.WaitForMultipleObjects([kill, pulse], False, 1000)
                        
                        # if kill signal received, break loop
                        if(result == win32con.WAIT_OBJECT_0): break
                        # elif timeout has passed, generate a pulse
                        elif(result == win32con.WAIT_OBJECT_0 + 1): self['event']()
                    except:
                        self.notifyOfError("Pacemaker shutdown.  Heartbeats will not be generated.")
                        win32event.SetEvent(kill)
            elif self.options['Verbose']: print "Pacemaker only supported in Windows at this time. " 
       
        try:
            self.thread = threading.Thread(target=__target, args=(timeout,) )
            self.thread.start()
        except:
            self.notifyOfError("Pacemaker thread exception.  Heartbeats will not be generated.")
        
    def basefilename(self):
        return os.path.join(self.options['OutputDir'], self.options['Prefix'].lower()) + '.' + str(self.params['ToolProjectName']).lower() + "." + str(datetime.now().strftime("%Y%m%d%H%M%S"))

    def notifyOfError(self,errorString=''):
    #   notifyOfError(errorString)
    #   Outputs reason for error and traceback stack to console.
        if self.options['Verbose']: print "Error: " + errorString
        exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
        if self.options['Debugging']: traceback.print_exception(exceptionType, exceptionValue, exceptionTraceback, limit=3, file=sys.stdout)    

    class __dtencoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, datetime): return obj.isoformat(' ')
            return json.JSONEncoder.default(self, obj)
        
    def __dumps(self, obj):
        return json.dumps(obj, cls=self.__dtencoder)

    def fromDICTwriteJSON(self, params={}):
    #   Open a new file using the logging scheme specified.
    #   Dump JSON output of the parameters provided.        
        if self.options['Logging']:            
            try:
                filename = self.basefilename() + '.json'
                out = {}
                for key in params: out[lower(key)] = params[key]
                with open(filename, 'a') as f:
                    f.write(self.__dumps(out)+'\n')
                    
            except:
                self.notifyOfError("Failed to generate output file.  Parameters were:\n"+str(params))
                try: os.remove(filename)
                except: pass
                
    class AbstractLogType(object):
        def __init__(self, params={}):
        #   params is a dictionary of k,v pairs.
        #   log is the parent concrete AbstractLog instance that called this
            self.__params = deepcopy(params)
            self.__queue = {}
        
        def __call__(self, ToolEvent='executed', ToolName=None, ToolVersion=None, Annotation=None, ToolStatus='notify', ToolProjectName=None, ToolProjectVersion=None, CommandLine=None, params={}):
        #   allows object to be called like a function via Object(...)
        #   implements a generic event logger for most applications, sends heartbeat by default
        #   capability can be employed as-is, extended, or overridden 
            try:
                d = self.__params
                for k in self.__queue:
                    d[k] = self.__queue[k]
                self.__queue = {}
                for k in params:
                    d[k] = params[k]
                if not d.has_key('EventType'): d['EventType'] = self.name
                self.log(ToolEvent, ToolName, ToolVersion, Annotation, ToolStatus, ToolProjectName, ToolProjectVersion, CommandLine, d)
            except:
                self.log.notifyOfError("Failed to generate output file.  Parameters were:\n"+str(params))
    
        def __getitem__(self, key):
        #   get a single item by dict reference
            if self.__params.has_key(key): return self.__params[key]
            else: return None 
            
        def __setitem__(self, key, value):
        #   set a single item by dict reference
            self.__params[key] = deepcopy(value)
            
        def queue(self, params={}):
        #   enqueue parameters for one-time output
            try:
                for key in params: self.__queue[key] = deepcopy(params[key])
            except:
                self.log.notifyOfError("Could not set queue by dictionary.")
            
        def set(self, params={}):
        #   set parameters for permanent output
            try:
                for key in params: self.__params[key] = deepcopy(params[key])
            except:
                self.log.notifyOfError("Could not set params by dictionary.")
            
        def open(self, params={}): self('opened', params=params)
        def close(self, params={}): self('closed', params=params)
        def start(self): self.queue({'StartTime': datetime.now()})
        def stop(self): self.queue({'StopTime': datetime.now()})
