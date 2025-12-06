File Manager - Final stable release
Features included:
- Login/register with roles. Default admin/admin123 created.
- Per-user 32 GiB quota.
- Folder support, delete, rename, search/filter.
- Chunked resumable uploads with server-side chunk tracking and localStorage-based resume helpers.
- Overwrite option supported. Upload finalization handles overwrite or renaming when duplicate.
- Image/video preview with Range support.
- Admin can view/manage other users via 'as_user' parameter.
- Client warns on page unload if there are pending uploads and stores pending upload metadata in localStorage so uploads can be resumed when the user returns and reselects files.

Run:
1. python -m venv venv
2. source venv/bin/activate  # or venv\Scripts\activate on Windows
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000/ and login with admin/admin123
