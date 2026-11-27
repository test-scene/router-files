"""Actual app navigation/shutdown handlers, independent of Tk."""
import ast
from pathlib import Path
from types import MethodType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


class Widget:
    def __init__(self, visible=False): self.visible=visible;self.options={}
    def grid(self): self.visible=True
    def grid_remove(self): self.visible=False
    def tkraise(self): pass
    def configure(self, **kwargs): self.options.update(kwargs)

source=ast.parse((Path(__file__).resolve().parents[1]/'app.py').read_text())
cls=next(node for node in source.body if isinstance(node,ast.ClassDef))
cls.bases=[]
methods={'_show_clouds','_set_list_mode','_open_route_builder','_close'}
cls.body=[node for node in cls.body if isinstance(node,ast.FunctionDef) and node.name in methods]
namespace={}
exec(compile(ast.fix_missing_locations(ast.Module(body=[cls],type_ignores=[])),'app.py','exec'),namespace)
App=namespace['WiFiVendorApp']


class CloudNavigationTests(unittest.TestCase):
    def setUp(self):
        self.cloud=Widget()
        self.cloud.flush=Mock(return_value=True)
        self.app=SimpleNamespace(_busy=False,_clouds_open=False,_details_open=False,_list_mode='available',
            _save_credentials=Mock(return_value=True),main_view=Widget(True),detail_view=Widget(),cloud_view=self.cloud,
            available_nav=Widget(),known_nav=Widget(),cloud_nav=Widget(),list_title=Widget(),_render_rows=Mock(),
            _route_window=None,_route_open=False,_close_after_relay=False,_closing=False,_save_job=None,_crack_stop=None,
            _status_value=SimpleNamespace(set=Mock()),destroy=Mock())
        for method in methods:setattr(self.app,method,MethodType(getattr(App,method),self.app))

    def test_cloud_page_and_return_to_network_history(self):
        self.app._show_clouds()
        self.assertTrue(self.cloud.visible)
        self.assertFalse(self.app.main_view.visible)
        self.app._set_list_mode('known')
        self.assertFalse(self.cloud.visible)
        self.assertTrue(self.app.main_view.visible)
        self.assertEqual(self.app._list_mode,'known')
        self.cloud.flush.assert_called_once()

    def test_invalid_profile_draft_blocks_navigation_instead_of_discarding_it(self):
        self.app._show_clouds()
        self.cloud.flush.return_value=False
        self.app._set_list_mode('available')
        self.assertTrue(self.cloud.visible)
        self.assertFalse(self.app.main_view.visible)

    def test_existing_running_route_can_be_focused_without_saving_invalid_draft(self):
        window=SimpleNamespace(winfo_exists=lambda:True,running=True,refresh_sources=Mock(),
                               deiconify=Mock(),lift=Mock(),focus_set=Mock(),focus_execution=Mock())
        self.app._route_window=window
        self.cloud.flush.return_value=False
        self.app._open_route_builder()
        window.focus_execution.assert_called_once()
        self.cloud.flush.assert_not_called()

    def test_route_editor_uses_page_host_and_hides_other_pages(self):
        page = SimpleNamespace(winfo_exists=lambda: True, running=False, show_editor=Mock(),
                               grid_remove=Mock(), model=SimpleNamespace(candidates=lambda: ([], [])))
        self.app.page_host = object()
        with patch.dict(namespace, RouteBuilderPage=Mock(return_value=page)):
            self.app._open_route_builder()
            namespace['RouteBuilderPage'].assert_called_once_with(self.app.page_host, self.app)
        self.assertIs(self.app._route_window, page)
        self.assertTrue(self.app._route_open)
        self.assertFalse(self.app.main_view.visible)
        self.assertFalse(self.cloud.visible)
        page.show_editor.assert_called_once()
        self.app._set_list_mode('known')
        page.grid_remove.assert_called_once()
        self.assertFalse(self.app._route_open)
        self.assertTrue(self.app.main_view.visible)

    def test_returning_to_editor_preserves_existing_route(self):
        page = SimpleNamespace(winfo_exists=lambda: True, running=False, show_editor=Mock())
        self.app._route_window = page
        self.app._open_route_builder()
        self.assertIs(self.app._route_window, page)
        page.show_editor.assert_called_once()

    def test_cloud_navigation_hides_editor(self):
        page = SimpleNamespace(winfo_exists=lambda: True, grid_remove=Mock())
        self.app._route_window, self.app._route_open = page, True
        self.app._show_clouds()
        page.grid_remove.assert_called_once()
        self.assertFalse(self.app._route_open)
        self.assertTrue(self.cloud.visible)

    def test_close_requests_stop_then_waits_for_worker_cleanup(self):
        window=SimpleNamespace(winfo_exists=lambda:True,running=True,request_stop=Mock())
        self.app._route_window=window
        self.app._close()
        window.request_stop.assert_called_once()
        self.assertTrue(self.app._close_after_relay)
        self.app.destroy.assert_not_called()
        window.running=False
        self.app._close()
        self.app.destroy.assert_called_once()

    def test_close_waits_for_feed_download_cleanup_before_destroying_root(self):
        self.cloud.close_feeds = Mock(return_value=False)
        self.app.after = Mock()
        self.app._close()
        self.app.destroy.assert_not_called()
        self.app.after.assert_called_once_with(100, self.app._close)
        self.cloud.close_feeds.return_value = True
        self.app._close()
        self.app.destroy.assert_called_once()
