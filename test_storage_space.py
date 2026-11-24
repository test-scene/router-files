"""Read-only space checks, secret handling and asynchronous cache lifecycle."""
import io
import json
import os
from pathlib import Path
import queue
import subprocess
from tempfile import TemporaryDirectory
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from storage_space import (SpaceRequest, SpaceState, SpaceChecks, make_space_request, parse_free,
    linux_command, probe_space, ssh_output, google_free)
from network_store import NetworkStore
from relay_store import RelayStore
from wifi_scanner import AccessPoint


class CapacityProbeTests(unittest.TestCase):
    def setUp(self):self.cancel=threading.Event()

    def test_zero_and_gib_values_and_unavailable_have_distinct_labels(self):
        self.assertEqual(SpaceState(free=0).text,'Свободно: 0 Б')
        self.assertEqual(SpaceState(free=1024**3).text,'Свободно: 1.0 ГиБ')
        self.assertEqual(SpaceState().text,'Свободно: Недоступно')
        self.assertIn('Проверка',SpaceState(checking=True).text)

    def test_linux_and_routeros_outputs_parse_bytes_without_confusing_memory(self):
        self.assertEqual(parse_free('WV_FREE_KIB=12\n',linux=True),12*1024)
        self.assertEqual(parse_free('free-memory: 123\nWV_FREE_BYTES=1.5MiB\n'),1572864)
        self.assertEqual(parse_free('WV_FREE_BYTES=0\n'),0)
        for output in ('WV_FREE_BYTES=-1','free-memory: 123','WV_FREE_BYTES=not known',
                       'WV_FREE_BYTES=1\nWV_FREE_BYTES=2','WV_FREE_BYTES=9999999999999999999999999'):
            self.assertIsNone(parse_free(output))

    def test_real_df_command_handles_missing_directory_and_shell_characters(self):
        with TemporaryDirectory() as folder:
            base=Path(folder)/"quoted '$() name";base.mkdir()
            output=subprocess.run(['/bin/sh','-c',linux_command(str(base/'not-created'))],
                check=True,capture_output=True,text=True).stdout
            free=parse_free(output,linux=True)
            self.assertIsInstance(free,int);self.assertGreaterEqual(free,0)

    def test_local_destination_walks_to_existing_parent(self):
        with TemporaryDirectory() as folder:
            with patch('storage_space.shutil.disk_usage',return_value=SimpleNamespace(free=77)) as usage:
                spec=SpaceRequest('pc',{},str(Path(folder)/'new'/'file.bin'))
                self.assertEqual(probe_space(spec,self.cancel),77)
                self.assertEqual(usage.call_args.args[0],Path(folder))

    def test_capacity_uses_native_ssh_and_saved_profile_port(self):
        target = dict(host='router.test', port=2222, user='user', password='fixture')
        spec = SpaceRequest('asus', target, '/tmp')
        with patch('storage_space.native_ssh.Transport') as transport:
            transport.return_value.run.return_value = 'WV_FREE_KIB=3'
            self.assertEqual(probe_space(spec, self.cancel), 3072)
            transport.return_value.run.assert_called_once_with(
                target, linux_command('/tmp'), 10, cancel=self.cancel, trust_new_host=False)

    def test_cancelled_probe_never_connects(self):
        self.cancel.set()
        with patch('storage_space.native_ssh.Transport') as transport:
            self.assertIsNone(ssh_output(SpaceRequest('asus', {}, '/tmp'), 'df', self.cancel))
            transport.assert_not_called()

    def test_routeros_asks_for_disk_space_and_netcraze_only_reads_existing_shell(self):
        mk=SpaceRequest('microtick',{},'')
        with patch('storage_space.ssh_output',return_value='WV_FREE_BYTES=1024') as ssh:
            self.assertEqual(probe_space(mk,self.cancel),1024)
        self.assertIn('free-hdd-space',ssh.call_args.args[1]);self.assertNotIn('free-memory',ssh.call_args.args[1])
        session=SimpleNamespace(login=Mock(),enter_shell=Mock(return_value=True),run=Mock(return_value='WV_FREE_KIB=9'),close=Mock())
        nc=SpaceRequest('netcraze',dict(host='router',port=23,user='admin',password='fixture'),'/opt/transfer')
        with patch('storage_space.netcraze.Session',return_value=session):self.assertEqual(probe_space(nc,self.cancel),9*1024)
        self.assertIn('df -Pk',session.run.call_args.args[0]);session.close.assert_called_once()
        session.enter_shell.return_value=False;session.close.reset_mock()
        with patch('storage_space.netcraze.Session',return_value=session):self.assertIsNone(probe_space(nc,self.cancel))
        session.close.assert_called_once()

    def test_unavailable_tools_connections_and_github_do_not_raise_or_guess(self):
        with patch('storage_space.ssh_output',side_effect=OSError('offline')):
            self.assertIsNone(probe_space(SpaceRequest('asus',{},'/tmp'),self.cancel))
        with patch('storage_space.netcraze_output',side_effect=OSError('fixture password')):
            self.assertIsNone(probe_space(SpaceRequest('netcraze',{},'/opt'),self.cancel))
        with patch('storage_space.build_opener') as opener:
            self.assertIsNone(probe_space(SpaceRequest('github',{'access_token':'fixture-token'}),self.cancel))
            opener.assert_not_called()


class GoogleQuotaTests(unittest.TestCase):
    class Response(io.BytesIO):status=200
    def setUp(self):
        self.cancel=threading.Event();self.requests=[];self.folder=None
        self.quota={'limit':'1000','usage':'350','usageInDrive':'10'}
        def open_request(request,timeout):
            self.requests.append(request)
            data=self.folder if '/files/' in request.full_url else {'storageQuota':self.quota}
            return self.Response(json.dumps(data).encode())
        self.opener=SimpleNamespace(open=open_request)
        self.patch=patch('storage_space.build_opener',return_value=self.opener);self.patch.start();self.addCleanup(self.patch.stop)
        self.profile={'access_token':'fixture-token','folder_id':''}

    def test_account_free_space_uses_total_usage_and_fixed_https_endpoint(self):
        self.assertEqual(google_free(self.profile,self.cancel),650)
        request=self.requests[0];url=urlsplit(request.full_url)
        self.assertEqual(url.scheme,'https');self.assertEqual(url.netloc,'www.googleapis.com')
        self.assertEqual(parse_qs(url.query)['fields'],['storageQuota(limit,usage)'])
        self.assertEqual(request.get_header('Authorization'),'Bearer fixture-token')
        self.assertNotIn('fixture-token',request.full_url)

    def test_owned_folder_is_checked_before_account_quota(self):
        self.profile['folder_id']='folder_1'
        self.folder={'mimeType':'application/vnd.google-apps.folder','ownedByMe':True}
        self.assertEqual(google_free(self.profile,self.cancel),650)
        self.assertEqual(len(self.requests),2)

    def test_shared_or_missing_folder_quota_is_unavailable(self):
        self.profile['folder_id']='folder_1'
        for data in ({'mimeType':'application/vnd.google-apps.folder','driveId':'shared','ownedByMe':True},
                     {'mimeType':'application/vnd.google-apps.folder','ownedByMe':False},{'mimeType':'text/plain'}):
            self.folder=data;self.requests=[]
            self.assertIsNone(google_free(self.profile,self.cancel));self.assertEqual(len(self.requests),1)

    def test_missing_unlimited_or_invalid_quota_does_not_become_zero(self):
        for data in ({'usage':'12'},{'limit':'100'},{'limit':'100','usage':'-1'},
                     {'limit':'100','usage':True},{'limit':'1e9','usage':'1'}):
            self.quota=data;self.assertIsNone(google_free(self.profile,self.cancel))
        self.quota={'limit':'100','usage':'200'};self.assertEqual(google_free(self.profile,self.cancel),0)

    def test_errors_are_returned_as_unavailable_and_cancel_prevents_network(self):
        self.opener.open=Mock(side_effect=OSError('fixture-token'))
        spec=SpaceRequest('gdrive',self.profile)
        self.assertIsNone(probe_space(spec,self.cancel))
        self.opener.open.reset_mock();self.cancel.set()
        self.assertIsNone(probe_space(spec,self.cancel));self.opener.open.assert_not_called()


class SpaceRequestTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);root=Path(self.temp.name)
        self.profiles=RelayStore(root/'profiles.json');self.networks=NetworkStore(root/'networks.json')
        self.ident='10:00:00:00:00:01';self.networks.remember([AccessPoint('Lab',self.ident,80,'6','WPA2','wlan0')])
        self.networks.save_credentials(self.ident,'wifi','admin','fixture')
        self.profiles.save_router(self.ident,dict(kind='netcraze',host='router',ssh_port=22,telnet_port=23))

    def test_router_probe_tracks_destination_filesystem_and_saved_credentials(self):
        node=dict(type='router',id=self.ident,kind='netcraze',path='storage:/transfer/a.bin')
        request=make_space_request(node,self.networks,self.profiles)
        self.assertEqual(request.path,'/opt/transfer');self.assertEqual(request.config['port'],23)
        self.assertNotIn('fixture',repr(request));self.assertNotIn('fixture',request.key)
        self.networks.save_credentials(self.ident,'wifi','admin','changed')
        self.assertNotEqual(make_space_request(node,self.networks,self.profiles).key,request.key)

    def test_invalid_router_path_or_missing_credentials_is_unavailable(self):
        node=dict(type='router',id=self.ident,kind='netcraze',path='/tmp/../bad')
        self.assertIsNone(make_space_request(node,self.networks,self.profiles))
        node['path']='';self.networks.save_credentials(self.ident,'wifi','admin','')
        self.assertIsNone(make_space_request(node,self.networks,self.profiles))


class SpaceCacheTests(unittest.TestCase):
    def test_duplicate_requests_share_probe_and_expiry_refreshes(self):
        calls=[]
        service=SpaceChecks(probe=lambda spec,cancel:calls.append(spec.kind) or 55)
        self.addCleanup(service.close)
        spec=SpaceRequest('pc',{},'/tmp');key=service.request(spec)
        service.queue.join();self.assertEqual(service.state(key).free,55)
        service.request(spec);self.assertEqual(calls,['pc'])
        with service.lock:service.cache[key]=(service.state(key),0)
        service.request(spec);service.queue.join();self.assertEqual(calls,['pc','pc'])

    def test_pause_cancels_pending_result_and_resume_can_check_same_node(self):
        started=threading.Event();release=threading.Event();count=[]
        def probe(spec,cancel):
            count.append(1)
            if len(count)==1:started.set();release.wait(2);return 1
            return 2
        service=SpaceChecks(probe=probe,workers=1);self.addCleanup(service.close)
        spec=SpaceRequest('pc',{},'/tmp');key=service.request(spec)
        self.assertTrue(started.wait(1));old_cancel=service.cancel
        service.pause();self.assertTrue(old_cancel.is_set())
        service.resume();service.request(spec);release.set();service.queue.join()
        self.assertEqual(service.state(key).free,2)
        service.close();service.close()
        service.request(SpaceRequest('pc',{},'/other'));self.assertTrue(service.closed)

    def test_worker_errors_and_github_immediately_show_unavailable(self):
        service=SpaceChecks(probe=Mock(side_effect=RuntimeError('secret')))
        self.addCleanup(service.close)
        key=service.request(SpaceRequest('asus',{},'/tmp'));service.queue.join()
        self.assertEqual(service.state(key).text,'Свободно: Недоступно')
        self.assertEqual(service.state(service.request(SpaceRequest('github',{}))).text,'Свободно: Недоступно')
        self.assertEqual(service.state(None).text,'Свободно: Недоступно')
