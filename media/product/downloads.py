import paramiko
import os
import time
import sys

# Force UTF-8 encoding for Windows
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)

# === CONFIG ===
hostname = 'ssh.pythonanywhere.com'
port = 22
username = 'Clickwelladmin'
password = 'clickWELL2005'
remote_dir = '/home/Clickwelladmin/DjangoAdmin/clickwell-backend/core/media/product'
local_dir = os.path.dirname(os.path.abspath(__file__))  # Save to same folder as script

# === CONNECT SSH & SFTP ===
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    print(f"🔌 Connecting to {hostname}...")
    ssh.connect(hostname=hostname, port=port, username=username, password=password)
    sftp = ssh.open_sftp()

    file_list = sftp.listdir(remote_dir)
    print(f"\n📂 Found {len(file_list)} files in {remote_dir}\n")

    for filename in file_list:
        remote_path = f"{remote_dir}/{filename}"
        local_path = os.path.join(local_dir, filename)

        try:
            file_size = sftp.stat(remote_path).st_size
            start_time = time.time()

            with sftp.file(remote_path, 'rb') as remote_file, open(local_path, 'wb') as local_file:
                bytes_read = 0
                while True:
                    data = remote_file.read(32768)
                    if not data:
                        break
                    local_file.write(data)
                    bytes_read += len(data)
                    elapsed = time.time() - start_time
                    speed_kb = (bytes_read / 1024) / elapsed if elapsed > 0 else 0
                    print(f"\r⬇️  {filename}: {bytes_read / 1024:.2f}/{file_size / 1024:.2f} KB @ {speed_kb:.2f} KB/s", end="")

            print(f"\n✅ Downloaded: {filename} ({file_size / 1024:.2f} KB)")

        except Exception as e:
            print(f"\n❌ Error downloading {filename}: {e}")

    sftp.close()
    ssh.close()
    print("\n🎉 All downloads completed.")

except Exception as e:
    print(f"\n❌ Connection failed: {e}")