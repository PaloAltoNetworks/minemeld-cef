cdef class Template(object):
    cdef dict attributes
    cdef dict globals
    cdef dict params

    def __init__(Template self, object attributes, object _globals, object params=None):
        if params is None:
            params = {}

        self.attributes = <dict?>attributes
        self.params = <dict?>params
        self.globals = <dict?>_globals

    def eval(Template self, dict locals_, dict data):
        cdef Environment genv
        cdef dict result
        cdef str gattr, attribute
        cdef Node gexpr, expr
        cdef object avalue, k, v

        result = {}
        genv = Environment(
            locals_={k: encapsulate_data(v) for k, v in locals_.iteritems()},
            data=data
        )

        init_environment(genv)

        for gattr, gexpr in self.globals.iteritems():
            try:
                genv[gattr] = eval_expression(genv, gexpr)

            except (AttributeError, TypeError, KeyError, ValueError):
                LOG.exception('Exception evaluating global %s', gattr)
                return None

        for attribute, expr in self.attributes.iteritems():
            try:
                avalue = eval_expression(Environment(parent=genv), expr)
                avalue = (<NakedNode>avalue).naked()

            except (AttributeError, TypeError, KeyError, ValueError):
                LOG.exception('Exception while evaluating %s' % attribute)
                return None

            result[attribute] = avalue

        return result

    @classmethod
    def compile(cls, template, params=None):
        _globals = {}
        for k in template.keys():
            if not k.startswith('$'):
                continue
            expr = template.pop(k, None)
            _globals[k[1:]] = compile_expression(expr)

        attributes = {}
        for attribute, expr in template.iteritems():
            attribute = unescape_scalar(attribute)
            attributes[attribute] = compile_expression(expr)

        return cls(attributes, _globals, params=None)

    def __repr__(self):
        return 'Template {%r}: %r %r' % (self.params, self.globals, self.attributes)
