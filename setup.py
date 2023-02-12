from setuptools import Extension, setup
import setuptools_scm

setup(
    ext_modules=[
        Extension(
            name="packetfrenzy.libmilter",
            libraries=["milter"],
            sources=['ext/packetfrenzy/libmiltermodule.c'],
            extra_compile_args=[
                "-D_FFR_WORKERS_POOL=1",
                f"-DVERSION=\"{setuptools_scm.get_version()}\""
            ],
        )
    ]
)
