import importlib
import logging

def classloader(module_type, module, artifact):
    package = "lib.{}.{}".format(module_type, module)
    try:
        imported = importlib.import_module(package)
    except Exception, e:
        logging.error("Error importing {}: {}".format(package, e))
        return
    try:
        module_class = getattr(imported, module)
        module_engine = module_class(artifact)
        return module_engine
    except Exception, e:
        logging.error("Error instantiating {}: {}".format(package, e))
