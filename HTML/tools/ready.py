import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from release_config import sdk_python_paths
sys.path[:0] = sdk_python_paths()
import bfrt_grpc.client as gc

client = gc.ClientInterface('127.0.0.1:50052', client_id=89, device_id=0,
                          perform_subscribe=False)
info = client.bfrt_info_get(sys.argv[1])
info.table_get('$PORT').info.key_field_name_list_get()
print('READY ' + sys.argv[1])
