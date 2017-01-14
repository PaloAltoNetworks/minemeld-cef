import operator

cdef int TAG_ABSTRACT = 0
cdef int TAG_ATOM = 1
cdef int TAG_DICT = 2
cdef int TAG_LIST = 3
cdef int TAG_SYMBOL = 4
cdef int TAG_ATTRIBUTEPATH = 5
cdef int TAG_PROCEDURECALL = 6
cdef int TAG_IF = 7
cdef int TAG_MATCH = 8
cdef int TAG_PROCEDURE = 9
cdef int TAG_ASSIGNMENT = 10
cdef int TAG_BUILTINPROCEDURE = 11
cdef int TAG_QUOTE = 12


cdef class Node(object):
    cdef int TAG

    def __init__(Node self):
        self.TAG = TAG_ABSTRACT

    def __repr__(Node self):
        return '%s %r' % (self.__class__.__name__, self)

    cdef Node eval(Node self, Environment env):
        raise NotImplemented('Hey, I am a basic node nothing to see here')


cdef class NakedNode(Node):
    cdef object naked(NakedNode self):
        raise NotImplemented('Hey, nothing to see here')


cdef class ApplyNode(Node):
    cdef Node apply(ApplyNode self, Environment env, ListNode args):
        raise NotImplemented('Hey, what am I supposed to do ?')

    def __call__(ApplyNode self, Environment env, ListNode args):
        return self.apply(env, args)


cdef list _ATOM_OPS = [
    operator.__lt__,
    operator.__le__,
    operator.__eq__,
    operator.__ne__,
    operator.__gt__,
    operator.__ge__
]


cdef class AtomNode(NakedNode):
    cdef list _ops
    cdef object atom

    def __init__(AtomNode self, object atom):
        self.TAG = TAG_ATOM
        self.atom = atom

    def __repr__(AtomNode self):
        return '%s %r' % (self.__class__.__name__, self.atom)

    def __richcmp__(AtomNode self, Node other, int op):
        if other.TAG != TAG_ATOM:
            return False

        if self.atom is None:
            return op == 2

        if op >= 6:
            raise NotImplemented('OP not implemented: %d', op)
        return _ATOM_OPS[op](self.atom, (<AtomNode>other).atom)

    def __hash__(AtomNode self):
        return self.atom.__hash__()

    def __nonzero__(AtomNode self):
        if self.atom is None:
            return False

        return self.atom.__nonzero__()

    cdef object naked(AtomNode self):
        return self.atom

    cdef Node eval(AtomNode self, Environment env):
        return self


cdef class DictNode(NakedNode):
    cdef dict items

    def __init__(DictNode self, object items):
        self.TAG = TAG_DICT
        self.items = <dict?>items

    def __repr__(DictNode self):
        return '%s {%s}' % (
            self.__class__.__name__,
            ', '.join(['%r: %r' % (k, v) for k, v in self.items.iteritems()])
        )

    def iteritems(DictNode self):
        return self.items.iteritems()

    cdef object naked(DictNode self):
        return {k.naked(): v.naked() for k,v in self.items.iteritems()}

    cdef Node eval(DictNode self, Environment env):
        return DictNode(
            {k.eval(env): v.eval(env) for k, v in self.items.iteritems()}
        )


cdef class ListNode(NakedNode):
    cdef list elements

    def __init__(ListNode self, object elements):
        self.TAG = TAG_LIST
        self.elements = <list?>elements

    def __repr__(ListNode self):
        return '%s [%s]' % (
            self.__class__.__name__,
            ', '.join(['%r' % e for e in self.elements])
        )

    def __len__(ListNode self):
        return self.elements.__len__()

    def __getitem__(ListNode self, object item):
        return self.elements.__getitem__(item)

    def __iter__(ListNode self):
        return self.elements.__iter__()

    cdef object naked(ListNode self):
        cdef NakedNode e

        return [e.naked() for e in self.elements]

    cdef Node eval(ListNode self, Environment env):
        cdef Node e

        return ListNode(
            [e.eval(env) for e in self.elements]
        )


cdef class SymbolNode(Node):
    cdef object symbol

    def __init__(SymbolNode self, symbol):
        self.TAG = TAG_SYMBOL
        self.symbol = symbol

    def __repr__(SymbolNode self):
        return '%s %s' % (self.__class__.__name__, self.symbol)

    cdef Node eval(SymbolNode self, Environment env):
        return env[self.symbol]


cdef class AttributePathNode(Node):
    cdef object attribute

    def __init__(AttributePathNode self, object attribute):
        self.TAG = TAG_ATTRIBUTEPATH
        self.attribute = attribute

    def __repr__(AttributePathNode self):
        return '%s %s' % (self.__class__.__name__, self.attribute)

    cdef Node eval(AttributePathNode self, Environment env):
        return encapsulate_data(env.get_data(self.attribute))


cdef class ProcedureCallNode(Node):
    cdef object fun
    cdef ListNode args

    def __init__(ProcedureCallNode self, object fun, object args):
        self.TAG = TAG_PROCEDURECALL
        self.fun = fun
        self.args = <ListNode?>args

    def __repr__(ProcedureCallNode self):
        return '%s %s(%s)' % (
            self.__class__.__name__,
            self.fun,
            ', '.join(["%r" % a for a in self.args])
        )

    cdef Node eval(ProcedureCallNode self, Environment env):
        cdef ListNode args
        cdef ApplyNode an
        cdef object result

        an = <ApplyNode?>env[self.fun]
        args = <ListNode?>self.args.eval(env)
        result = an.apply(env, args)

        return result


cdef class QuoteNode(Node):
    cdef object arg

    def __init__(self, arg):
        self.TAG = TAG_QUOTE
        self.arg = arg

    def __repr__(self):
        return '%s %r' % (self.__class__.__name__, self.arg)

    cdef Node eval(QuoteNode self, Environment env):
        return self.arg


cdef class IfNode(Node):
    cdef Node test
    cdef Node conseq
    cdef Node alt

    def __init__(IfNode self, object test, object conseq, object alt):
        self.TAG = TAG_IF
        self.test = <Node?>test
        self.conseq = <Node?>conseq
        self.alt = <Node?>alt

    def __repr__(IfNode self):
        return '%s %r %r %r' % (
            self.__class__.__name__,
            self.test,
            self.conseq,
            self.alt
        )

    cdef Node eval(IfNode self, Environment env):
        cdef AtomNode test

        test = self.test.eval(env)
        if test:
            return self.conseq.eval(env)
        return self.alt.eval(env)


cdef class MatchNode(Node):
    cdef ListNode patterns
    cdef Node default
    cdef Node var

    def __init__(MatchNode self, object var, object patterns, object default=None):
        if default is None:
            default = ATOM_NONE

        self.TAG = TAG_MATCH
        self.var = <Node?>var
        self.patterns = <ListNode?>patterns
        self.default = <Node?>default

    def __repr__(MatchNode self):
        return '%s %r %r %r' % (
            self.__class__.__name__,
            self.var,
            self.patterns,
            self.default
        )

    cdef Node eval(MatchNode self, Environment env):
        cdef object test
        cdef Node pattern
        cdef Node pexpr

        var = self.var.eval(env)
        for pattern, pexpr in self.patterns:
            peval = pattern.eval(env)

            if peval.TAG == TAG_ATOM:
                test = (peval == var)
            elif peval.TAG == TAG_PROCEDURE or peval.TAG == TAG_BUILTINPROCEDURE:
                test = (<ApplyNode>peval).apply(env, ListNode([var]))
            else:
                continue

            if test:
                return pexpr.eval(env)

        return self.default.eval(env)


cdef class ProcedureNode(ApplyNode):
    cdef ListNode formals
    cdef Node body

    def __init__(ProcedureNode self, object formals, object body):
        self.TAG = TAG_PROCEDURE
        self.formals = <ListNode?>formals
        self.body = <Node?>body

    def __repr__(ProcedureNode self):
        return '%s %r %r' % (
            self.__class__.__name__,
            self.formals,
            self.body
        )

    cdef Node apply(ProcedureNode self, Environment env, ListNode args):
        cdef SymbolNode x
        cdef Environment senv

        senv = Environment(
            parent=env,
            locals_={i[0]: i[1] for i in zip([x.symbol for x in self.formals], args)}
        )
        return self.body.eval(senv)

    cdef Node eval(ProcedureNode self, Environment env):
        return self


cdef class BuiltinProcedureNode(ProcedureNode):
    cdef object fun
    cdef object name

    def __init__(BuiltinProcedureNode self, object fun, object name=None):
        self.TAG = TAG_BUILTINPROCEDURE
        self.fun = fun
        self.name = name if name is not None else '<unnamed>'

    cdef Node apply(BuiltinProcedureNode self, Environment env, ListNode args):
        cdef Node result

        result = <Node?>self.fun(env, args)
        return result

    def __repr__(BuiltinProcedureNode self):
        return '%s %s' % (self.__class__.__name__, self.name)


cdef class AssignmentNode(Node):
    cdef SymbolNode var
    cdef Node expr

    def __init__(AssignmentNode self, object var, object expr):
        self.TAG = TAG_ASSIGNMENT
        self.var = <SymbolNode?>var
        self.expr = <Node?>expr

    def __repr__(AssignmentNode self):
        return '%s %r %r' % (self.__class__.__name__, self.var, self.expr)

    cdef Node eval(AssignmentNode self, Environment env):
        env[self.var.symbol] = self.expr.eval(env)
        return atom(None)


cdef object ATOM_NONE = AtomNode(None)


def atom(data):
    if data is None:
        return ATOM_NONE
    return AtomNode(data)


def unescape_scalar(scalar):
    if isinstance(scalar, unicode) or isinstance(scalar, str):
        if scalar.startswith('\\$'):
            return unicode(scalar[1:])

    return scalar


cdef Node encapsulate_data(object data):
    dtype = type(data)
    if dtype == list:
        return ListNode([encapsulate_data(e) for e in data])
    elif dtype == dict:
        return DictNode({
            encapsulate_data(k): encapsulate_data(v) for k, v in data.iteritems()
        })

    return atom(data)


def compile_expression(expr):
    if isinstance(expr, unicode) or isinstance(expr, str):
        if expr[0] == '$':
            if expr[1] == '$':
                return AttributePathNode(unicode(expr[2:]))

            return SymbolNode(unicode(expr[1:]))

        return atom(unescape_scalar(expr))

    elif isinstance(expr, list):
        return ListNode(map(compile_expression, expr))

    elif isinstance(expr, dict):
        if len(expr) == 1:
            fun, args = next(expr.iteritems())
            if fun == '$if':
                return IfNode(
                    compile_expression(args[0]),
                    compile_expression(args[1]),
                    compile_expression(args[2]) if len(args) > 2 else None
                )

            elif fun == '$lambda':
                return ProcedureNode(
                    compile_expression(args[0]) if isinstance(args[0], list) else compile_expression([args[0]]),
                    compile_expression(args[1])
                )

            elif fun == '$set!' or fun == '$define':
                return AssignmentNode(
                    compile_expression(args[0]),
                    compile_expression(args[1])
                )

            elif fun == '$match':
                return MatchNode(
                    compile_expression(args[0]),
                    compile_expression(args[1]),
                    compile_expression(args[2]) if len(args) > 2 else atom(None)
                )

            elif fun == '$quote':
                return QuoteNode(compile_expression(args))

            elif fun[0] == '$':
                pcn = ProcedureCallNode(
                    unicode(fun[1:]),
                    compile_expression(args) if isinstance(args, list) else compile_expression([args])
                )

                quicklambda = False
                if isinstance(args, list):
                    quicklambda = '$_' in args
                elif isinstance(args, str) or isinstance(args, unicode):
                    quicklambda = args == '$_'

                if not quicklambda:
                    return pcn

                return ProcedureNode(
                    compile_expression(['$_']),
                    pcn
                )


        return DictNode({compile_expression(k): compile_expression(v) for k, v in expr.iteritems()})

    return atom(expr)


cdef Node eval_expression(Environment env, Node expr):
    return expr.eval(env)
