from setuptools import setup

setup(name="cvim_tools",
      version="1.0",
      description="Display log files",
      packages=['cvimlog'],
      entry_points={'console_scripts':
                        ['cvimlog = cvimlog.log:main']})
