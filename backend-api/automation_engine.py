"""
Linux-Link Automation Engine

Provides macro system and task automation capabilities with conditional logic
and scheduling support for complex workflow automation.
"""

import os
import json
import time
import logging
import subprocess
import threading
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import schedule
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ActionType(Enum):
    COMMAND = "command"
    API_CALL = "api_call"
    CONDITION = "condition"
    DELAY = "delay"
    LOOP = "loop"
    VARIABLE = "variable"


class MacroStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MacroAction:
    """Represents a single action in a macro"""
    id: str
    type: ActionType
    command: str
    parameters: Dict[str, Any] = None
    condition: str = None
    timeout: int = 30
    retry_count: int = 0


class ConditionEvaluator:
    """Evaluates conditional expressions for macro execution"""
    
    def __init__(self):
        self.variables = {}
        self.system_info = {}
        self._update_system_info()
        logger.info("Condition evaluator initialized")
    
    def _update_system_info(self):
        """Update system information for condition evaluation"""
        try:
            import psutil
            self.system_info = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'time_hour': datetime.now().hour,
                'time_minute': datetime.now().minute,
                'day_of_week': datetime.now().weekday(),
                'processes': [p.name() for p in psutil.process_iter(['name'])]
            }
        except Exception as e:
            logger.warning(f"Failed to update system info: {e}")
            self.system_info = {}
    
    def set_variable(self, name: str, value: Any):
        """Set a variable for condition evaluation"""
        self.variables[name] = value
        logger.debug(f"Set variable {name} = {value}")
    
    def get_variable(self, name: str) -> Any:
        """Get a variable value"""
        return self.variables.get(name)
    
    def evaluate_condition(self, condition: str, context: Dict[str, Any] = None) -> bool:
        """
        Evaluate a conditional expression
        
        Supported operators:
        - Comparison: ==, !=, <, >, <=, >=
        - Logical: and, or, not
        - System: cpu_percent, memory_percent, disk_usage, time_hour, etc.
        - Variables: $variable_name
        - Process checks: process_running("name")
        - File checks: file_exists("path")
        """
        try:
            self._update_system_info()
            
            # Prepare evaluation context
            eval_context = {
                **self.system_info,
                **self.variables,
                **(context or {}),
                'process_running': self._process_running,
                'file_exists': self._file_exists,
                'command_success': self._command_success
            }
            
            # Replace variable references
            processed_condition = self._process_variables(condition)
            
            # Evaluate the condition safely
            result = self._safe_eval(processed_condition, eval_context)
            logger.debug(f"Condition '{condition}' evaluated to {result}")
            return bool(result)
            
        except Exception as e:
            logger.error(f"Failed to evaluate condition '{condition}': {e}")
            return False
    
    def _process_variables(self, condition: str) -> str:
        """Process variable references in condition string"""
        import re
        
        def replace_var(match):
            var_name = match.group(1)
            value = self.variables.get(var_name, 0)
            return str(value)
        
        return re.sub(r'\$(\w+)', replace_var, condition)
    
    def _safe_eval(self, expression: str, context: Dict[str, Any]) -> Any:
        """Safely evaluate expression with restricted context"""
        # Only allow safe built-ins
        safe_builtins = {
            'abs': abs, 'bool': bool, 'float': float, 'int': int,
            'len': len, 'max': max, 'min': min, 'str': str,
            'True': True, 'False': False, 'None': None
        }
        
        # Create restricted globals
        restricted_globals = {
            '__builtins__': safe_builtins,
            **context
        }
        
        return eval(expression, restricted_globals, {})
    
    def _process_running(self, process_name: str) -> bool:
        """Check if a process is running"""
        return process_name in self.system_info.get('processes', [])
    
    def _file_exists(self, file_path: str) -> bool:
        """Check if a file exists"""
        return os.path.exists(file_path)
    
    def _command_success(self, command: str) -> bool:
        """Check if a command executes successfully"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['type'] = self.type.value
        return data


@dataclass
class MacroExecution:
    """Represents a macro execution instance"""
    execution_id: str
    macro_id: str
    status: MacroStatus
    started_at: float
    completed_at: Optional[float] = None
    current_action: int = 0
    variables: Dict[str, Any] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        return data


class AutomationError(Exception):
    """Base exception for automation operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class MacroEngine:
    """Core macro execution engine"""
    
    def __init__(self):
        self.macros = {}
        self.executions = {}
        self.variables = {}
        self.condition_evaluator = ConditionEvaluator()
        self._load_macros()
        logger.info("Macro engine initialized")
    
    def create_macro(self, macro_id: str, name: str, description: str, 
                    actions: List[MacroAction]) -> bool:
        """Create a new macro"""
        try:
            macro = {
                'id': macro_id,
                'name': name,
                'description': description,
                'actions': [action.to_dict() for action in actions],
                'created_at': time.time(),
                'updated_at': time.time(),
                'execution_count': 0
            }
            
            self.macros[macro_id] = macro
            self._save_macros()
            
            logger.info(f"Created macro: {macro_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create macro {macro_id}: {e}")
            return False    
    de
f execute_macro(self, macro_id: str, variables: Dict[str, Any] = None) -> str:
        """Execute a macro and return execution ID"""
        try:
            if macro_id not in self.macros:
                raise AutomationError(
                    f"Macro not found: {macro_id}",
                    "MACRO_NOT_FOUND"
                )
            
            execution_id = f"{macro_id}_{int(time.time())}"
            
            execution = MacroExecution(
                execution_id=execution_id,
                macro_id=macro_id,
                status=MacroStatus.RUNNING,
                started_at=time.time(),
                variables=variables or {}
            )
            
            # Sync variables with condition evaluator
            if variables:
                for name, value in variables.items():
                    self.condition_evaluator.set_variable(name, value)
            
            self.executions[execution_id] = execution
            
            # Start execution in background thread
            thread = threading.Thread(
                target=self._execute_macro_thread,
                args=(execution_id,)
            )
            thread.daemon = True
            thread.start()
            
            logger.info(f"Started macro execution: {execution_id}")
            return execution_id
        
        except Exception as e:
            logger.error(f"Failed to execute macro {macro_id}: {e}")
            raise AutomationError(
                f"Failed to execute macro: {str(e)}",
                "MACRO_EXECUTION_FAILED"
            )
    
    def _execute_macro_thread(self, execution_id: str):
        """Execute macro in background thread"""
        try:
            execution = self.executions[execution_id]
            macro = self.macros[execution.macro_id]
            
            for i, action_dict in enumerate(macro['actions']):
                if execution.status != MacroStatus.RUNNING:
                    break
                
                execution.current_action = i
                
                # Execute action
                success = self._execute_action(action_dict, execution)
                
                if not success:
                    execution.status = MacroStatus.FAILED
                    execution.error_message = f"Action {i} failed"
                    break
            
            if execution.status == MacroStatus.RUNNING:
                execution.status = MacroStatus.COMPLETED
            
            execution.completed_at = time.time()
            
            # Update macro statistics
            macro['execution_count'] += 1
            macro['last_executed'] = time.time()
            self._save_macros()
            
            logger.info(f"Macro execution completed: {execution_id} ({execution.status.value})")
        
        except Exception as e:
            logger.error(f"Macro execution thread failed: {e}")
            if execution_id in self.executions:
                self.executions[execution_id].status = MacroStatus.FAILED
                self.executions[execution_id].error_message = str(e)
    
    def _execute_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute a single macro action"""
        try:
            action_type = ActionType(action_dict['type'])
            
            # Check condition if present
            if action_dict.get('condition'):
                if not self.condition_evaluator.evaluate_condition(
                    action_dict['condition'], 
                    execution.variables
                ):
                    logger.debug(f"Skipping action due to condition: {action_dict['condition']}")
                    return True  # Skip action but don't fail
            
            if action_type == ActionType.COMMAND:
                return self._execute_command_action(action_dict, execution)
            elif action_type == ActionType.API_CALL:
                return self._execute_api_action(action_dict, execution)
            elif action_type == ActionType.DELAY:
                return self._execute_delay_action(action_dict, execution)
            elif action_type == ActionType.VARIABLE:
                return self._execute_variable_action(action_dict, execution)
            elif action_type == ActionType.CONDITION:
                return self._execute_condition_action(action_dict, execution)
            elif action_type == ActionType.LOOP:
                return self._execute_loop_action(action_dict, execution)
            else:
                logger.warning(f"Unknown action type: {action_type}")
                return False
        
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            return False
    
    def _execute_command_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute command action"""
        try:
            command = self._substitute_variables(action_dict['command'], execution.variables)
            timeout = action_dict.get('timeout', 30)
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Store command output in variables
            execution.variables['last_command_output'] = result.stdout
            execution.variables['last_command_error'] = result.stderr
            execution.variables['last_command_returncode'] = result.returncode
            
            return result.returncode == 0
        
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {action_dict['command']}")
            return False
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False
    
    def _execute_api_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute API call action"""
        try:
            # This would integrate with other controllers
            # For now, return success
            return True
        except Exception as e:
            logger.error(f"API action failed: {e}")
            return False
    
    def _execute_delay_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute delay action"""
        try:
            delay = float(action_dict.get('parameters', {}).get('seconds', 1))
            time.sleep(delay)
            return True
        except Exception as e:
            logger.error(f"Delay action failed: {e}")
            return False
    
    def _execute_variable_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute variable assignment action"""
        try:
            var_name = action_dict.get('parameters', {}).get('name')
            var_value = action_dict.get('parameters', {}).get('value')
            
            if var_name:
                execution.variables[var_name] = self._substitute_variables(str(var_value), execution.variables)
            
            return True
        except Exception as e:
            logger.error(f"Variable action failed: {e}")
            return False
    
    def _execute_condition_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute conditional action with if/else logic"""
        try:
            condition = action_dict.get('parameters', {}).get('condition', '')
            if_actions = action_dict.get('parameters', {}).get('if_actions', [])
            else_actions = action_dict.get('parameters', {}).get('else_actions', [])
            
            if self.condition_evaluator.evaluate_condition(condition, execution.variables):
                # Execute if actions
                for if_action in if_actions:
                    if not self._execute_action(if_action, execution):
                        return False
            else:
                # Execute else actions
                for else_action in else_actions:
                    if not self._execute_action(else_action, execution):
                        return False
            
            return True
        except Exception as e:
            logger.error(f"Condition action failed: {e}")
            return False
    
    def _execute_loop_action(self, action_dict: Dict, execution: MacroExecution) -> bool:
        """Execute loop action with iteration control"""
        try:
            loop_type = action_dict.get('parameters', {}).get('type', 'count')
            actions = action_dict.get('parameters', {}).get('actions', [])
            
            if loop_type == 'count':
                count = int(action_dict.get('parameters', {}).get('count', 1))
                for i in range(count):
                    execution.variables['loop_index'] = i
                    for loop_action in actions:
                        if not self._execute_action(loop_action, execution):
                            return False
            
            elif loop_type == 'while':
                condition = action_dict.get('parameters', {}).get('condition', 'False')
                max_iterations = int(action_dict.get('parameters', {}).get('max_iterations', 100))
                iteration = 0
                
                while (self.condition_evaluator.evaluate_condition(condition, execution.variables) 
                       and iteration < max_iterations):
                    execution.variables['loop_index'] = iteration
                    for loop_action in actions:
                        if not self._execute_action(loop_action, execution):
                            return False
                    iteration += 1
            
            elif loop_type == 'foreach':
                items = action_dict.get('parameters', {}).get('items', [])
                for i, item in enumerate(items):
                    execution.variables['loop_index'] = i
                    execution.variables['loop_item'] = item
                    for loop_action in actions:
                        if not self._execute_action(loop_action, execution):
                            return False
            
            return True
        except Exception as e:
            logger.error(f"Loop action failed: {e}")
            return False
    
    def _substitute_variables(self, text: str, variables: Dict[str, Any]) -> str:
        """Substitute variables in text"""
        try:
            result = text
            for var_name, var_value in variables.items():
                placeholder = f"${{{var_name}}}"
                result = result.replace(placeholder, str(var_value))
            return result
        except Exception:
            return text
    

    
    def get_macro_status(self, execution_id: str) -> Optional[MacroExecution]:
        """Get macro execution status"""
        return self.executions.get(execution_id)
    
    def stop_macro(self, execution_id: str) -> bool:
        """Stop macro execution"""
        try:
            if execution_id in self.executions:
                self.executions[execution_id].status = MacroStatus.PAUSED
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to stop macro {execution_id}: {e}")
            return False
    
    def get_macros(self) -> List[Dict[str, Any]]:
        """Get list of all macros"""
        return list(self.macros.values())
    
    def delete_macro(self, macro_id: str) -> bool:
        """Delete a macro"""
        try:
            if macro_id in self.macros:
                del self.macros[macro_id]
                self._save_macros()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete macro {macro_id}: {e}")
            return False
    
    def _load_macros(self):
        """Load macros from persistent storage"""
        try:
            macros_file = os.path.expanduser('~/.linux_link_macros.json')
            if os.path.exists(macros_file):
                with open(macros_file, 'r') as f:
                    data = json.load(f)
                    self.macros = data.get('macros', {})
                    logger.info(f"Loaded {len(self.macros)} macros")
        except Exception as e:
            logger.debug(f"Could not load macros: {e}")
            self.macros = {}
    
    def _save_macros(self):
        """Save macros to persistent storage"""
        try:
            macros_file = os.path.expanduser('~/.linux_link_macros.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'macros': self.macros
            }
            
            with open(macros_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved {len(self.macros)} macros")
        except Exception as e:
            logger.error(f"Failed to save macros: {e}")


class TaskScheduler:
    """Task scheduling system"""
    
    def __init__(self, macro_engine: MacroEngine):
        self.macro_engine = macro_engine
        self.scheduled_tasks = {}
        self.scheduler_thread = None
        self.running = False
        self._load_scheduled_tasks()
        logger.info("Task scheduler initialized")
    
    def schedule_macro(self, task_id: str, macro_id: str, schedule_expr: str, 
                      variables: Dict[str, Any] = None) -> bool:
        """Schedule a macro to run on a schedule"""
        try:
            task = {
                'id': task_id,
                'macro_id': macro_id,
                'schedule': schedule_expr,
                'variables': variables or {},
                'created_at': time.time(),
                'last_run': None,
                'run_count': 0,
                'enabled': True
            }
            
            self.scheduled_tasks[task_id] = task
            self._save_scheduled_tasks()
            
            # Update schedule
            self._update_schedule()
            
            logger.info(f"Scheduled macro {macro_id} as task {task_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to schedule macro: {e}")
            return False
    
    def start_scheduler(self):
        """Start the task scheduler"""
        if not self.running:
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
            self.scheduler_thread.daemon = True
            self.scheduler_thread.start()
            logger.info("Task scheduler started")
    
    def stop_scheduler(self):
        """Stop the task scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Task scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                time.sleep(5)
    
    def _update_schedule(self):
        """Update the schedule with current tasks"""
        schedule.clear()
        
        for task_id, task in self.scheduled_tasks.items():
            if not task.get('enabled', True):
                continue
            
            try:
                # Parse schedule expression (simplified)
                schedule_expr = task['schedule']
                
                if schedule_expr.startswith('every '):
                    # Parse "every X minutes/hours/days"
                    parts = schedule_expr.split()
                    if len(parts) >= 3:
                        interval = int(parts[1])
                        unit = parts[2].rstrip('s')  # Remove plural 's'
                        
                        if unit == 'minute':
                            schedule.every(interval).minutes.do(self._run_scheduled_task, task_id)
                        elif unit == 'hour':
                            schedule.every(interval).hours.do(self._run_scheduled_task, task_id)
                        elif unit == 'day':
                            schedule.every(interval).days.do(self._run_scheduled_task, task_id)
                
                elif ':' in schedule_expr:
                    # Parse time format "HH:MM"
                    schedule.every().day.at(schedule_expr).do(self._run_scheduled_task, task_id)
                
                elif schedule_expr.startswith('cron '):
                    # Basic cron-like support
                    self._parse_cron_expression(schedule_expr[5:], task_id)
                
                elif schedule_expr == 'startup':
                    # Run once at startup
                    self._run_scheduled_task(task_id)
                
                elif schedule_expr.startswith('on '):
                    # Parse "on monday", "on weekdays", etc.
                    day_part = schedule_expr[3:].lower()
                    if day_part == 'monday':
                        schedule.every().monday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'tuesday':
                        schedule.every().tuesday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'wednesday':
                        schedule.every().wednesday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'thursday':
                        schedule.every().thursday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'friday':
                        schedule.every().friday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'saturday':
                        schedule.every().saturday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'sunday':
                        schedule.every().sunday.do(self._run_scheduled_task, task_id)
                    elif day_part == 'weekdays':
                        for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']:
                            getattr(schedule.every(), day).do(self._run_scheduled_task, task_id)
                    elif day_part == 'weekends':
                        schedule.every().saturday.do(self._run_scheduled_task, task_id)
                        schedule.every().sunday.do(self._run_scheduled_task, task_id)
            
            except Exception as e:
                logger.error(f"Failed to schedule task {task_id}: {e}")
    
    def _parse_cron_expression(self, cron_expr: str, task_id: str):
        """Parse basic cron expression (simplified)"""
        try:
            # Basic cron format: minute hour day month weekday
            parts = cron_expr.split()
            if len(parts) != 5:
                logger.error(f"Invalid cron expression: {cron_expr}")
                return
            
            minute, hour, day, month, weekday = parts
            
            # Handle simple cases
            if minute == '0' and hour != '*':
                # Run at specific hour
                if hour.isdigit():
                    schedule.every().day.at(f"{hour}:00").do(self._run_scheduled_task, task_id)
            
            elif minute != '*' and hour != '*':
                # Run at specific time
                if minute.isdigit() and hour.isdigit():
                    schedule.every().day.at(f"{hour}:{minute}").do(self._run_scheduled_task, task_id)
            
            # More complex cron parsing would go here
            
        except Exception as e:
            logger.error(f"Failed to parse cron expression {cron_expr}: {e}")
    
    def enable_task(self, task_id: str) -> bool:
        """Enable a scheduled task"""
        try:
            if task_id in self.scheduled_tasks:
                self.scheduled_tasks[task_id]['enabled'] = True
                self._save_scheduled_tasks()
                self._update_schedule()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to enable task {task_id}: {e}")
            return False
    
    def disable_task(self, task_id: str) -> bool:
        """Disable a scheduled task"""
        try:
            if task_id in self.scheduled_tasks:
                self.scheduled_tasks[task_id]['enabled'] = False
                self._save_scheduled_tasks()
                self._update_schedule()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to disable task {task_id}: {e}")
            return False
    
    def get_next_run_time(self, task_id: str) -> Optional[float]:
        """Get next scheduled run time for a task"""
        try:
            # This would require integration with the schedule library
            # to get next run times for specific jobs
            return None
        except Exception as e:
            logger.error(f"Failed to get next run time for {task_id}: {e}")
            return None
    
    def get_task_history(self, task_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get execution history for a scheduled task"""
        try:
            # This would require storing execution history
            # For now, return empty list
            return []
        except Exception as e:
            logger.error(f"Failed to get task history for {task_id}: {e}")
            return []
    
    def _run_scheduled_task(self, task_id: str):
        """Run a scheduled task"""
        try:
            task = self.scheduled_tasks.get(task_id)
            if not task:
                return
            
            execution_id = self.macro_engine.execute_macro(
                task['macro_id'],
                task.get('variables', {})
            )
            
            # Update task statistics
            task['last_run'] = time.time()
            task['run_count'] += 1
            task['last_execution_id'] = execution_id
            
            self._save_scheduled_tasks()
            
            logger.info(f"Executed scheduled task {task_id}: {execution_id}")
        
        except Exception as e:
            logger.error(f"Scheduled task execution failed: {e}")
    
    def get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get list of scheduled tasks"""
        return list(self.scheduled_tasks.values())
    
    def delete_scheduled_task(self, task_id: str) -> bool:
        """Delete a scheduled task"""
        try:
            if task_id in self.scheduled_tasks:
                del self.scheduled_tasks[task_id]
                self._save_scheduled_tasks()
                self._update_schedule()
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete scheduled task {task_id}: {e}")
            return False
    
    def _load_scheduled_tasks(self):
        """Load scheduled tasks from storage"""
        try:
            tasks_file = os.path.expanduser('~/.linux_link_scheduled_tasks.json')
            if os.path.exists(tasks_file):
                with open(tasks_file, 'r') as f:
                    data = json.load(f)
                    self.scheduled_tasks = data.get('tasks', {})
                    logger.info(f"Loaded {len(self.scheduled_tasks)} scheduled tasks")
        except Exception as e:
            logger.debug(f"Could not load scheduled tasks: {e}")
            self.scheduled_tasks = {}
    
    def _save_scheduled_tasks(self):
        """Save scheduled tasks to storage"""
        try:
            tasks_file = os.path.expanduser('~/.linux_link_scheduled_tasks.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'tasks': self.scheduled_tasks
            }
            
            with open(tasks_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved {len(self.scheduled_tasks)} scheduled tasks")
        except Exception as e:
            logger.error(f"Failed to save scheduled tasks: {e}")


class AutomationEngine:
    """Main automation engine"""
    
    def __init__(self):
        self.macro_engine = MacroEngine()
        self.task_scheduler = TaskScheduler(self.macro_engine)
        self.task_scheduler.start_scheduler()
        logger.info("Automation engine initialized")
    
    def create_macro(self, macro_id: str, name: str, description: str, 
                    actions: List[Dict[str, Any]]) -> bool:
        """Create a new macro"""
        try:
            macro_actions = []
            for action_dict in actions:
                action = MacroAction(
                    id=action_dict.get('id', f"action_{len(macro_actions)}"),
                    type=ActionType(action_dict['type']),
                    command=action_dict['command'],
                    parameters=action_dict.get('parameters', {}),
                    condition=action_dict.get('condition'),
                    timeout=action_dict.get('timeout', 30),
                    retry_count=action_dict.get('retry_count', 0)
                )
                macro_actions.append(action)
            
            return self.macro_engine.create_macro(macro_id, name, description, macro_actions)
        
        except Exception as e:
            logger.error(f"Failed to create macro: {e}")
            return False
    
    def execute_macro(self, macro_id: str, variables: Dict[str, Any] = None) -> str:
        """Execute a macro"""
        return self.macro_engine.execute_macro(macro_id, variables)
    
    def get_macro_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get macro execution status"""
        execution = self.macro_engine.get_macro_status(execution_id)
        return execution.to_dict() if execution else None
    
    def stop_macro(self, execution_id: str) -> bool:
        """Stop macro execution"""
        return self.macro_engine.stop_macro(execution_id)
    
    def get_macros(self) -> List[Dict[str, Any]]:
        """Get list of macros"""
        return self.macro_engine.get_macros()
    
    def delete_macro(self, macro_id: str) -> bool:
        """Delete a macro"""
        return self.macro_engine.delete_macro(macro_id)
    
    def schedule_macro(self, task_id: str, macro_id: str, schedule_expr: str, 
                      variables: Dict[str, Any] = None) -> bool:
        """Schedule a macro"""
        return self.task_scheduler.schedule_macro(task_id, macro_id, schedule_expr, variables)
    
    def get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get scheduled tasks"""
        return self.task_scheduler.get_scheduled_tasks()
    
    def delete_scheduled_task(self, task_id: str) -> bool:
        """Delete scheduled task"""
        return self.task_scheduler.delete_scheduled_task(task_id)
    
    def get_automation_stats(self) -> Dict[str, Any]:
        """Get automation statistics"""
        macros = self.get_macros()
        scheduled_tasks = self.get_scheduled_tasks()
        
        return {
            'total_macros': len(macros),
            'total_scheduled_tasks': len(scheduled_tasks),
            'active_executions': len([e for e in self.macro_engine.executions.values() 
                                    if e.status == MacroStatus.RUNNING]),
            'total_executions': len(self.macro_engine.executions),
            'scheduler_running': self.task_scheduler.running
        }


# Global automation engine instance
_automation_engine = None


def get_automation_engine() -> AutomationEngine:
    """Get global automation engine instance"""
    global _automation_engine
    if _automation_engine is None:
        _automation_engine = AutomationEngine()
    return _automation_engine


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    ae = get_automation_engine()
    
    # Create example macro
    actions = [
        {
            'type': 'command',
            'command': 'echo "Hello from macro"'
        },
        {
            'type': 'delay',
            'parameters': {'seconds': 2}
        },
        {
            'type': 'command',
            'command': 'date'
        }
    ]
    
    ae.create_macro('test_macro', 'Test Macro', 'A simple test macro', actions)
    
    # Execute macro
    execution_id = ae.execute_macro('test_macro')
    print(f"Started execution: {execution_id}")
    
    # Check status
    time.sleep(1)
    status = ae.get_macro_status(execution_id)
    print(f"Status: {status}")