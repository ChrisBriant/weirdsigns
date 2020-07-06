from weirdsigns import app
import os

@app.context_processor
def media_path():
    return os.path.join(app.instance_path, 'media/img')
