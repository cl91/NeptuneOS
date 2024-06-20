project(battc C)

add_definitions(-D_BATTERYCLASS_)

add_driver(battc battc.c battc.rc)
spec2def(battc battc.spec ${Arch})
set_dll_def(battc battc.def)
