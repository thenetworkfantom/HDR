from recommonmark.transform import AutoStructify
import requests


project = 'HDR'
copyright = '2023, HACKTHEHECK'
author = 'HackTheHeck TN'

url = "https://raw.githubusercontent.com/"
response = requests.get(url, timeout=5)

if response.status_code == 200:
    release = response.text
extensions = ['recommonmark']
templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

source_suffix = {
    '.rst': 'restructuredtext',
    '.txt': 'markdown',
    '.md': 'markdown',
    '.html': 'html',
}
master_doc = 'index'

def setup(app):
    app.add_config_value(
        'recommonmark_config',
        {
            'auto_toc_tree_section': 'HDR',
            'enable_math': False,
            'enable_inline_math': False,
            'enable_eval_rst': True,
        },
        True,
    )
    app.add_transform(AutoStructify)
