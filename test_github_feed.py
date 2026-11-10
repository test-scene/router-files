import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import queue
import subprocess
import threading
from urllib.error import HTTPError
from urllib.parse import urlsplit
import uuid
import unittest
from unittest.mock import patch

import test_github_transfer as support
from github_feed import FeedFile, parse_feed, serialize_feed, merge_feed, feed_path, git_sha, GitHubFeedClient, DownloadCancelled
from relay.model import Artifact, Problem


def entry(path='uploads/file.bin', commit='a'*40, data=b'hello'):
    return FeedFile(path, commit, git_sha(data), len(data), hashlib.md5(data).hexdigest(), '2026-10-28T12:00:00+00:00')


class AtomModelTests(unittest.TestCase):
    def test_round_trip_supports_unicode_and_xml_sensitive_file_names(self):
        item=entry('uploads/файл & <text>.bin')
        xml=serialize_feed([item],support.profile())
        self.assertIn(b'<feed',xml);self.assertIn(b'&amp;',xml)
        self.assertEqual(parse_feed(xml),[item])
        self.assertNotIn(b'fixture_token',xml)

    def test_merge_deduplicates_and_keeps_recent_fifty_files(self):
        entries=[entry(f'uploads/{n}.bin') for n in range(50)]
        new=entry('uploads/new.bin')
        merged=merge_feed(entries,new)
        self.assertEqual(len(merged),50);self.assertEqual(merged[0],new)
        self.assertEqual(merge_feed(merged,new),merged)

    def test_catalog_feed_identity_differs_by_repository(self):
        first=serialize_feed([entry()],support.profile())
        second=serialize_feed([entry()],support.profile(repository='other'))
        self.assertNotEqual(first,second)
        self.assertEqual(parse_feed(first),parse_feed(second))

    def test_entities_and_wrong_feed_types_are_rejected(self):
        for xml in (b'<!DOCTYPE x [<!ENTITY e "bad">]><feed/>',b'<feed/>',b'<html>login</html>',b'x'*262145):
            with self.subTest(xml=xml[:30]),self.assertRaises(Problem):parse_feed(xml)

    def test_malformed_file_metadata_is_rejected(self):
        for changes in (dict(path='../escape'),dict(commit='not-a-sha'),dict(blob='wrong'),dict(size=-1),
                        dict(md5='bad'),dict(uploaded_at='yesterday')):
            values=dict(path='uploads/file.bin',commit='a'*40,blob=git_sha(b'x'),size=1,
                        md5=hashlib.md5(b'x').hexdigest(),uploaded_at='2026-10-28T00:00:00+00:00')
            values.update(changes)
            with self.subTest(changes=changes),self.assertRaises(Problem):FeedFile(**values)


class Response(io.BytesIO):
    status=200


class StubOpener:
    """Adapt the same executable API stub to urllib without any sockets."""
    def __init__(self,fixture):self.fixture,self.requests=fixture,[]
    def open(self,request,timeout=30):
        self.requests.append(request.full_url)
        stem=self.fixture.root/('pc-'+uuid.uuid4().hex)
        settings='request = "GET"\nurl = '+json.dumps(request.full_url)+'\noutput = '+json.dumps(str(stem)+'.body')+'\n'
        for name,value in request.header_items():settings+='header = '+json.dumps(name+': '+value)+'\n'
        config=Path(str(stem)+'.cfg');config.write_text(settings)
        result=subprocess.run([str(self.fixture.curl),'-q','--config',str(config)],capture_output=True,text=True,check=True)
        raw=Path(str(stem)+'.body').read_bytes();status=int(result.stdout)
        if status!=200:raise HTTPError(request.full_url,status,'API error',{},io.BytesIO(raw))
        return Response(raw)


class AtomDownloadTests(unittest.TestCase):
    state=support.GitHubShellTests.state
    change=support.GitHubShellTests.change
    def setUp(self):
        support.GitHubShellTests.setUp(self)
        self.opener=StubOpener(self)
        with patch('github_feed.build_opener',return_value=self.opener):self.client=GitHubFeedClient(support.profile())

    def upload(self,path='uploads/file.bin'):
        result=self.uploader.upload(self.artifact,path,{})
        return result

    def test_missing_profile_folder_is_reported_and_poll_never_downloads_file_content(self):
        with self.assertRaisesRegex(Problem,'Папка'):self.client.poll()
        result=self.upload()
        items=self.client.poll()
        self.assertEqual(len(items),1);self.assertEqual(items[0].commit,result.commit_sha)
        self.assertEqual(items[0].path,'uploads/file.bin')
        file_url='/git/blobs/'+result.blob_sha
        self.assertFalse(any(url.endswith(file_url) for url in self.opener.requests))
        self.assertFalse(any(method=='GET' and path==file_url for method,path in self.state()['calls']))
        self.assertTrue(any(url.endswith('/git/blobs/'+git_sha(serialize_feed(items,support.profile()))) for url in self.opener.requests))
        self.assertFalse(any(Path(path).name=='github-readback.bin' for path in self.task.jobs.reads))

    def test_poll_preserves_recent_versions_and_user_downloads_selected_file(self):
        first=self.upload('uploads/first.bin')
        self.source.write_bytes(b'second file')
        data=self.source.read_bytes();self.artifact=Artifact('asus',str(self.source),'second',len(data),hashlib.md5(data).hexdigest())
        self.upload('uploads/second.bin')
        files=self.client.poll()
        self.assertEqual([item.path for item in files],['uploads/second.bin','uploads/first.bin'])
        target=self.root/'chosen.bin'
        self.client.download(files[1],target,threading.Event())
        self.assertEqual(target.read_bytes(),self.data)
        self.assertEqual(files[1].commit,first.commit_sha)
        self.assertEqual(list(self.root.glob('.wifi-download-*.part')),[])

    def test_repeated_poll_caches_atom_blob_without_redownloading_it(self):
        self.upload();self.client.poll()
        before=sum('/git/blobs/' in url for url in self.opener.requests)
        self.client.poll()
        self.assertEqual(sum('/git/blobs/' in url for url in self.opener.requests),before)

    def test_download_cancel_removes_partial_and_keeps_existing_target(self):
        self.upload();item=self.client.poll()[0]
        target=self.root/'old.bin';target.write_bytes(b'old content');stop=threading.Event()
        def progress(count,total):
            if count:stop.set()
        with self.assertRaises(DownloadCancelled):self.client.download(item,target,stop,overwrite=True,progress=progress)
        self.assertEqual(target.read_bytes(),b'old content')
        self.assertEqual(list(self.root.glob('.wifi-download-*.part')),[])

    def test_corrupt_download_is_rejected_without_overwriting_target(self):
        self.upload();item=self.client.poll()[0]
        self.change(corrupt_download=True)
        target=self.root/'old.bin';target.write_bytes(b'old content')
        with self.assertRaises(Problem):self.client.download(item,target,threading.Event(),overwrite=True)
        self.assertEqual(target.read_bytes(),b'old content')
        self.assertEqual(list(self.root.glob('.wifi-download-*.part')),[])

    def test_existing_destination_needs_explicit_overwrite(self):
        self.upload();item=self.client.poll()[0]
        target=self.root/'old.bin';target.write_bytes(b'old')
        with self.assertRaises(Problem):self.client.download(item,target,threading.Event())
        self.assertEqual(target.read_bytes(),b'old')
        self.client.download(item,target,threading.Event(),overwrite=True)
        self.assertEqual(target.read_bytes(),self.data)

    def test_server_cannot_change_atom_file_identity_before_download(self):
        self.upload();item=self.client.poll()[0]
        fake=FeedFile(item.path,item.commit,'f'*40,item.size,item.md5,item.uploaded_at)
        target=self.root/'bad.bin'
        with self.assertRaisesRegex(Problem,'версию'):self.client.download(fake,target,threading.Event())
        self.assertFalse(target.exists())

    def test_atom_publish_failure_preserves_source_and_retry_does_not_upload_file_again(self):
        # Fail after the primary file was committed, while publishing catalog metadata.
        original=self.task.jobs.execute
        dropped=[False]
        def execute(command,label,**kwargs):
            result=original(command,label,**kwargs)
            calls=self.state()['calls']
            if calls and calls[-1][0]=='PUT' and calls[-1][1].endswith('.wifi-relay.atom') and not dropped[0]:
                dropped[0]=True;raise support.scp.Lost('feed acknowledgement lost')
            return result
        self.task.jobs.execute=execute
        transaction={}
        with self.assertRaises(support.scp.Lost):self.uploader.upload(self.artifact,'uploads/retry.bin',transaction)
        self.assertTrue(self.source.exists())
        self.uploader.upload(self.artifact,'uploads/retry.bin',transaction)
        puts=[path for method,path in self.state()['calls'] if method=='PUT' and path.endswith('/retry.bin')]
        self.assertEqual(len(puts),1)
        self.assertEqual(len(self.client.poll()),1)
