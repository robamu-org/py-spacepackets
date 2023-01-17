import enum
from warnings import warn


class Subservice(enum.IntEnum):
    TC_ENABLE_PERIODIC_HK_GEN = 5
    TC_DISABLE_PERIODIC_HK_GEN = 6
    TC_ENABLE_PERIODIC_DIAGNOSTICS_GEN = 7
    TC_DISABLE_PERIODIC_DIAGNOSTICS_GEN = 8

    TM_REPORT_HK_REPORT_STRUCTURES = 9
    TM_REPORT_DIAG_REPORT_STRUCTURES = 11

    TM_HK_DEFINITIONS_REPORT = 10
    TM_DIAG_DEFINITION_REPORT = 12

    TM_HK_REPORT = 25
    TM_DIAGNOSTICS_REPORT = 26

    TC_GENERATE_ONE_PARAMETER_REPORT = 27
    TC_GENERATE_ONE_DIAGNOSTICS_REPORT = 28

    TC_MODIFY_PARAMETER_REPORT_COLLECTION_INTERVAL = 31
    TC_MODIFY_DIAGNOSTICS_REPORT_COLLECTION_INTERVAL = 32


class Subservices(Subservice):
    def __init_subclass__(cls, **kwargs):
        """This throws a deprecation warning on subclassing."""
        warn(f"{cls.__name__} will be deprecated.", DeprecationWarning, stacklevel=2)
        super().__init_subclass__(**kwargs)

    def __init__(self, *args, **kwargs):
        """This throws a deprecation warning on initialization."""
        warn(
            f"{self.__class__.__name__} will be deprecated.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
