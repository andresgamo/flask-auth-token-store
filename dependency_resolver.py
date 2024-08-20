class DependencyResolver:
    _dependencies = {}

    @classmethod
    def register(cls, name, instance):
        cls._dependencies[name] = instance

    @classmethod
    def get(cls, name):
        return cls._dependencies.get(name)