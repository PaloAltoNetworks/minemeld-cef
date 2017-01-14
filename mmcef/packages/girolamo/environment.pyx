cdef class Environment(dict):
    cdef dict data
    cdef Environment parent

    def __init__(Environment self, dict data=None, dict locals_=None, Environment parent=None):
        dict.__init__(self)  # faster than super(Environment, ...)

        self.data = data
        self.parent = parent

        if locals_ is not None:
            self.update(locals_)

    def get_data(Environment self, object key, object default=None):
        if self.data is not None:
            return self.data.get(key, default)

        if self.parent is not None:
            return self.parent.get_data(key, default)

        raise RuntimeError('data is not defined')

    def get_data_attributes(Environment self):
        if self.data is None:
            return []

        return self.data.keys()

    def __missing__(Environment self, object key):
        if self.parent is not None:
            return self.parent[key]

        raise KeyError('variable \'%s\' not defined' % key)

    def __contains__(Environment self, object item):
        result = super(Environment, self).__contains__(item)
        if not result:
            return item in self.parent

        return result
