import time

from netaddr import IPNetwork
from netaddr.core import AddrFormatError


def is_eq(Environment env, ListNode args):
    return atom(args.elements[0] == args.elements[1])


def is_in(Environment env, ListNode args):
    return atom(args.elements[0] in args.elements[1])


def car(Environment env, ListNode args):
    cdef ListNode l

    if args[0] == ATOM_NONE:
        return ATOM_NONE

    l = <ListNode?>args[0]

    if len(l.elements) == 0:
        return ATOM_NONE

    return l.elements[0]


def cdr(Environment env, ListNode args):
    cdef ListNode l

    if args[0] == ATOM_NONE:
        return ATOM_NONE

    l = <ListNode?>args[0]

    return ListNode(l.elements[1:])


def list_join(Environment env, ListNode args):
    cdef NakedNode e
    cdef ListNode l
    cdef NakedNode s

    if (<Node?>args[1]) == ATOM_NONE:
        return ATOM_NONE
    l = <ListNode?>args[1]
    s = <NakedNode?>args[0]

    return atom(s.naked().join([e.naked() for e in l.elements]))


def list_length(Environment env, ListNode args):
    cdef ListNode l

    l = <ListNode?>args[0]
    return atom(len(l.elements))


def list_intersection(Environment env, ListNode args):
    cdef ListNode s1
    cdef ListNode s2

    s1 = <ListNode?>args[0]
    s2 = <ListNode?>args[1]
    return ListNode(list(set(s1.elements) & set(s2.elements)))


def attributes_list(Environment env, ListNode args):
    return encapsulate_data(env.get_data_attributes())


def attributes_get(Environment env, ListNode args):
    cdef NakedNode e

    e = <NakedNode?>args[0]
    return encapsulate_data(env.get_data(e.naked()))


def ip_unicast(Environment env, ListNode args):
    cdef AtomNode ip

    ip = <AtomNode?>args[0]
    try:
        return atom(IPNetwork(ip.naked()).is_unicast())

    except AddrFormatError:
        LOG.exception('exception in ip_unicast')
        return ATOM_NONE


def ip_prefixlen(Environment env, ListNode args):
    cdef AtomNode ip

    ip = <AtomNode?>args[0]
    try:
        return atom(IPNetwork(ip.naked()).prefixlen)

    except AddrFormatError:
        return ATOM_NONE


def begin(Environment env, ListNode args):
    return args[-1]


cdef void init_environment(Environment env):
    env['is-null'] = BuiltinProcedureNode(
        lambda env, args: atom(bool(args[0] == ATOM_NONE))
    )
    env['null?'] = env['is-null']

    env['and'] = BuiltinProcedureNode(
        lambda env, args: atom(bool(args[0] and args[1]))
    )
    env['or'] = BuiltinProcedureNode(
        lambda env, args: atom(bool(args[0] or args[1]))
    )
    env['not'] = BuiltinProcedureNode(
        lambda env, args: atom(not bool(args[0]))
    )

    env['eq'] = BuiltinProcedureNode(is_eq)
    env['eq?'] = env['eq']
    env['lt'] = BuiltinProcedureNode(
        lambda env, args: atom(args[0] < args[1])
    )
    env['lt?'] = BuiltinProcedureNode(
        lambda env, args: atom(args[0] < args[1])
    )
    env['in?'] = BuiltinProcedureNode(is_in)
    env['in'] = BuiltinProcedureNode(is_in)

    env['is-list'] = BuiltinProcedureNode(
        lambda env, args: atom(isinstance(args[0], ListNode))
    )
    env['list?'] = BuiltinProcedureNode(
        lambda env, args: atom(isinstance(args[0], ListNode))
    )
    env['car'] = BuiltinProcedureNode(car, name='car')
    env['cdr'] = BuiltinProcedureNode(cdr, name='cdr')
    env['list-join'] = BuiltinProcedureNode(list_join)
    env['list-length'] = BuiltinProcedureNode(list_length)
    env['list-intersection'] = BuiltinProcedureNode(
        list_intersection,
        name='list-intersection'
    )

    env['attributes-list'] = BuiltinProcedureNode(attributes_list)
    env['attributes-get'] = BuiltinProcedureNode(attributes_get)

    env['is-unicast'] = BuiltinProcedureNode(ip_unicast, name='unicast?')
    env['unicast?'] = BuiltinProcedureNode(ip_unicast, name='unicast?')
    env['ip-prefixlen'] = BuiltinProcedureNode(ip_prefixlen, name='ip-prefixlen')

    env['time-millisecond-since-epoch'] = BuiltinProcedureNode(
        lambda env, args: atom(int(time.time()*1000))
    )

    env['begin'] = BuiltinProcedureNode(
        begin, name='begin'
    )
