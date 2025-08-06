from flask import Flask, send_from_directory, abort, jsonify, send_file
import os
import zipfile
import io

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. قائمة جميع الملفات في المجلد
@app.route('/list_files', methods=['GET'])
def list_files():
    files = [f for f in os.listdir(BASE_DIR) if os.path.isfile(os.path.join(BASE_DIR, f))]
    return jsonify(files)

# 2. تحميل كل الملفات كـ ZIP
@app.route('/download_all', methods=['GET'])
def download_all_files():
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        for filename in os.listdir(BASE_DIR):
            filepath = os.path.join(BASE_DIR, filename)
            if os.path.isfile(filepath):
                zip_file.write(filepath, arcname=filename)
    zip_buffer.seek(0)
    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name='project_files.zip')

# 3. قراءة أي ملف منفرد (كما شرحنا سابقًا)
@app.route('/raw/<path:filename>', methods=['GET'])
def get_raw_file(filename):
    try:
        return send_from_directory(BASE_DIR, filename, as_attachment=False)
    except FileNotFoundError:
        abort(404)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
