TARGET := iphone:clang:latest:15.0
INSTALL_TARGET_PROCESSES = lsd cfprefsd
FINALPACKAGE = 1
#THEOS_PACKAGE_SCHEME = rootless
ARCHS = arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rootlesshooks

rootlesshooks_FILES = $(wildcard *.x)
rootlesshooks_CFLAGS = -Werror -fobjc-arc
rootlesshooks_LDFLAGS = -rpath @loader_path/fallback -ljbpath

lsd.x_CFLAGS = -fno-objc-arc #lsd using mrc

include $(THEOS_MAKE_PATH)/tweak.mk

after-rootlesshooks-all::
	install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate @rpath/CydiaSubstrate.framework/CydiaSubstrate $(THEOS_OBJ_DIR)/rootlesshooks.dylib
	ldid -S $(THEOS_OBJ_DIR)/rootlesshooks.dylib
