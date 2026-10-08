"""Bounded expansion of NSX nested service references, including entry paths."""
from validation import array, object_value, strings

class ServiceResolver:
    def __init__(self, services, max_depth=16, max_entries=10000):
        self.services = services
        self.entries = {}
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.steps = 0
        for service in services.values():
            for entry in array(service.get('service_entries'), 'service_entries'):
                object_value(entry, 'service entry')
                path = entry.get('path')
                if path:
                    if path in self.entries or path in services:
                        raise ValueError('Duplicate service entry path: ' + path)
                    self.entries[path] = entry

    def expand(self, rule):
        refs = strings(rule.get('services', []), 'services')
        inline = array(rule.get('service_entries', []), 'inline service_entries')
        if refs == ['ANY']:
            if inline: raise ValueError('Mixed ANY and inline service entries')
            return None  # ALL protocols, caller chooses its supported domain.
        self.steps = 0
        output = []
        def visit_entry(entry, stack):
            self.steps += 1
            if self.steps > 100000: raise ValueError('Service expansion work limit exceeded')
            object_value(entry, 'service entry')
            if entry.get('marked_for_delete') is not None and entry['marked_for_delete'] is not False:
                raise ValueError('Deleted or ambiguous service entry')
            if entry.get('resource_type') == 'NestedServiceServiceEntry':
                path = entry.get('nested_service_path')
                if not isinstance(path, str) or not path:
                    raise ValueError('Nested service path required')
                visit_path(path, stack)
            else:
                output.append(entry)
                if len(output)>self.max_entries:
                    raise ValueError('Service expansion entry limit exceeded')
        def visit_path(path, stack):
            if path in stack: raise ValueError('Cyclic nested service reference: ' + path)
            if len(stack)>=self.max_depth: raise ValueError('Nested service depth limit exceeded')
            stack = stack + (path,)
            if path in self.services:
                for entry in self.services[path]['service_entries']:visit_entry(entry, stack)
            elif path in self.entries:
                visit_entry(self.entries[path], stack)
            else:raise ValueError('Unresolved nested service: ' + path)
        for path in refs:visit_path(path, ())
        for entry in inline:visit_entry(entry, ())
        if not output: raise ValueError('Empty service expansion')
        return output
