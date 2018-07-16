SUMMARY = "generate minimal and customized core dump files on Linux"
DESCRIPTION = "minicoredumper is a program that handles the creation of core dump files on \
Linux. It can produce much smaller core dump files by making use of sparse \
files, compression, and allowing the user to configure what parts of the \
process memory image should be dumped."
HOMEPAGE = "https://www.linutronix.de/minicoredumper"
BUGTRACKER = "https://bugs.linuxfoundation.org/buglist.cgi?product=Diamon&component=minicoredumper"

SECTION = "devel"

LICENSE = "BSD-2-Clause & LGPL-2.1"
LICENSE_minicoredumper = "BSD-2-Clause"
LICENSE_minicoredumper-utils = "BSD-2-Clause"
LICENSE_libminicoredumper-dev = "LGPL-2.1"
LICENSE_libminicoredumper = "LGPL-2.1"

LIC_FILES_CHKSUM = " \
	file://COPYING;md5=709087c2ed0acda54a4d91497a889e42 \
	file://COPYING.BSD;md5=b915ac80d5236d6aa659cb986daf00e5 \
	file://COPYING.LGPLv2.1;md5=321bf41f280cf805086dd5a720b37785 \
	"

DEPENDS = "elfutils json-c pkgconfig"
RDEPENDS_${PN} = "base-files"

SRC_URI = " \
	https://www.linutronix.de/minicoredumper/files/minicoredumper-${PV}.tar.xz \
	file://remove-script-deps.patch \
	"

SRC_URI[md5sum] = "543001b51de20a8b17fce462a7dfa377"
SRC_URI[sha256sum] = "6b5355f94b8ba676515b4243752f231ace200dbb9195065bc2fdd397ae20d8c5"

PACKAGECONFIG ??= ""

EXTRA_OECONF = ""

PACKAGES += "minicoredumper-utils libminicoredumper-dev libminicoredumper"

FILES_${PN} = " \
	${sbindir}/minicoredumper \
	${sbindir}/minicoredumper_regd \
	${sysconfdir}/minicoredumper \
	${sysconfdir}/init.d \
	${sysconfdir}/default \
	${localstatedir}/crash \
	${localstatedir}/run \
	/run \
	"
FILES_minicoredumper-utils = " \
	${bindir}/coreinject \
	${sbindir}/minicoredumper_trigger \
	"
FILES_libminicoredumper-dev = " \
	${includedir}/* \
	${libdir}/lib*.a \
	${libdir}/lib*.la \
	${libdir}/lib*.so \
	${libdir}/pkgconfig/* \
	"
FILES_${PN}-dbg = " \
	${libdir}/.debug \
	${bindir}/.debug \
	${sbindir}/.debug \
	${prefix}/src/debug \
	"
FILES_libminicoredumper = "${libdir}/lib*.so.*"
FILES_libminicoredumper-doc = "${mandir}/*/*"

INITSCRIPT_NAME = "minicoredumper"
INITSCRIPT_PARAMS = "defaults 8"

inherit autotools update-rc.d
