try:
    from burp import IBurpExtender
    from burp import IExtensionStateListener
    from burp import IProxyListener
    from burp import IParameter
    from burp import IRequestInfo
    from burp import IInterceptedProxyMessage
    from burp import IContextMenuFactory
    from burp import IContextMenuInvocation
    from javax import swing
    from java.net import URL
    from burp import ITab
    from javax.swing import JMenuItem
    from javax.swing import JLabel
    from javax.swing import JButton
    from javax.swing import JTextArea
    from javax.swing import JTextField
    from javax.swing import JPanel
    from javax.swing import JScrollPane
    from javax.swing import JCheckBox
    from javax.swing import JTabbedPane
    from javax.swing.text import Utilities
    from javax.swing.text import DefaultHighlighter
    from java.awt import GridBagLayout
    from java.awt import GridBagConstraints
    from java.awt import Insets
    from java.awt import Color
    from java.awt import Font
    import java.lang as lang
    from java.awt.event import MouseEvent
    from java.awt.event import MouseAdapter
    import re
    import os
    import thread
    from urlparse import parse_qs, urlparse
    from json import dumps
    import xml.dom.minidom

except ImportError:
    print 'Failed to load dependencies. This issue maybe caused by using an unstable Jython version.'

callbacks = None
helpers = None
NAME = 'BoShikhaGETPOST'
VERSION = '2.0'
DEBUG = False

extension_enable = True
in_scope_only = True
change_method_to_post = True

change_to_get = True





def debug2console(title, *args):
    if DEBUG:
        print "[ debug ]", "Begin", title
        for arg in args:
            print arg
        print "[ debug ]", "End", title

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''

    return helpers.bytesToString(bytes)

class BurpExtender(IBurpExtender, IProxyListener, ITab):
    def getTabCaption(self):  ### ITab
        return NAME

    def getUiComponent(self):  ### ITab
        return self.tabs

    def setFontItalic(self, label):
        label.setFont(Font(label.getFont().getName(), Font.ITALIC, label.getFont().getSize()))

    def setFontBold(self, label):
        label.setFont(Font('Serif', Font.BOLD, label.getFont().getSize()))

    def registerExtenderCallbacks(self, this_callbacks):  ### IBurpExtender
        global callbacks, helpers
        global extension_enable, in_scope_only
        global change_method_to_post
     

        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName(NAME)

        self.settings = JPanel(GridBagLayout())
        c = GridBagConstraints()

        self.extension_enable_box = JCheckBox('Enable extension', extension_enable)
        self.setFontBold(self.extension_enable_box)
        self.extension_enable_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(5, 5, 5, 5)
        c.gridx = 0
        c.gridy = 0
        c.gridwidth = 1
        c.weightx = 1
        c.fill = GridBagConstraints.NONE
        c.anchor = GridBagConstraints.WEST
        self.settings.add(self.extension_enable_box, c)

        self.in_scope_only_box = JCheckBox('Modify only in-scope requests', in_scope_only)
        self.setFontBold(self.in_scope_only_box)
        self.in_scope_only_box.setForeground(Color(0, 0, 153))
        c.insets = Insets(40, 5, 5, 5)
        c.gridx = 0
        c.gridy = 1
        self.settings.add(self.in_scope_only_box, c)

     

        

        self.change_method_to_post_box = JCheckBox('Change HTTP method to POST', change_method_to_post)
        self.setFontBold(self.change_method_to_post_box)
        self.change_method_to_post_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 6
        self.settings.add(self.change_method_to_post_box, c)

        change_method_to_post_lbl = JLabel('Check to convert PUT/DELETE/PATCH method to POST in all requests.')
        self.setFontItalic(change_method_to_post_lbl)
        c.gridx = 0
        c.gridy = 7
        self.settings.add(change_method_to_post_lbl, c)

        

       
        self.change_to_get_box = JCheckBox('Change to GET', change_to_get)
        self.setFontBold(self.change_to_get_box)
        self.change_to_get_box.setForeground(Color(0, 0, 153))
        c.gridx = 0
        c.gridy = 12
        self.settings.add(self.change_to_get_box, c)

        change_to_get_lbl = JLabel('Check to convert POST/PUT/DELETE/PATCH url-encoded requests to GET.')
        self.setFontItalic(change_to_get_lbl)
        c.gridx = 0
        c.gridy = 13
        self.settings.add(change_to_get_lbl, c)


        self.tabs = JTabbedPane()
        self.tabs.addTab('Settings', self.settings)
        

        callbacks.customizeUiComponent(self.tabs)
        callbacks.addSuiteTab(self)
        
        callbacks.registerProxyListener(self)



        print "Successfully loaded %s v%s by Mohammed alsaggaf " % (NAME, VERSION)

    def text_area_to_list(self, text_area):
        l = text_area.getText().strip().split('\n')
        return l if l != [''] else []

   

    def processProxyMessage(self, messageIsRequest, message):  ### IProxyListener
        global callbacks
        extension_enable = self.extension_enable_box.isSelected()
        if not extension_enable:
            return  # Do nothing

        in_scope_only = self.in_scope_only_box.isSelected()
        change_method_to_post = self.change_method_to_post_box.isSelected()
     
       
        change_to_get = self.change_to_get_box.isSelected()

        request_response = message.getMessageInfo()
        request_info = helpers.analyzeRequest(request_response)
        request_method = request_info.getMethod()

        if in_scope_only and not callbacks.isInScope(request_info.getUrl()):
            return  # Do nothing when URL is not in scope

        if not messageIsRequest or request_method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return  # Do nothing

        

        http_service = request_response.getHttpService()
        request = request_response.getRequest()
        headers = request_info.getHeaders()
        parameters = request_info.getParameters()

        new_headers = headers

        #new added
        offset = helpers.analyzeRequest(http_service, request).getBodyOffset()
        body = request[offset:]
        body = re.sub(",\s*,", ",", body)
        body = re.sub("{\s*,", "{", body)
        body = re.sub(",\s*}", "}", body)

        request = helpers.buildHttpMessage(headers, body)
         
        offset = helpers.analyzeRequest(http_service, request).getBodyOffset()
        body = request[offset:]
        
       #new Added


        if (change_method_to_post and request_method != 'POST') or (change_to_get  and \
                                request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED):
            for i in range(len(new_headers)):
                if new_headers[i].startswith("PUT") or new_headers[i].startswith("DELETE") \
                        or new_headers[i].startswith("PATCH"):
                    new_headers[i] = new_headers[i].replace(request_method, 'POST', 1)
                    break

        new_request = helpers.buildHttpMessage(new_headers, body)  # Create new request with valid Content-Length
        
        if (change_method_to_post and request_method != 'POST') or (change_to_get  and \
                                request_info.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED):
            param1 = helpers.buildParameter('method', request_method, IParameter.PARAM_URL)
            param2 = helpers.buildParameter('_method', request_method, IParameter.PARAM_URL)
            new_request = helpers.addParameter(new_request, param1)
            new_request = helpers.addParameter(new_request, param2)
            if change_to_get:
                new_request = helpers.toggleRequestMethod(new_request)  # Change any URL-encoded request to GET
                self._callbacks.addToSiteMap(request_response)
        message.setInterceptAction(IInterceptedProxyMessage.ACTION_FOLLOW_RULES_AND_REHOOK)
        message.getMessageInfo().setRequest(new_request)
        message.getMessageInfo().setHighlight('red')
        self._callbacks.addToSiteMap(request_response)
class TextAreaMouseListener(MouseAdapter):
    def __init__(self, text_area):
        self.text_area = text_area

    def getSelected(self):
        return (self.start, self.value)

    def mousePressed(self, event):  ### MouseAdapter
        if event.getButton() != MouseEvent.BUTTON1:
            return

        offset = self.text_area.viewToModel(event.getPoint())
        rowStart = Utilities.getRowStart(self.text_area, offset)
        rowEnd = Utilities.getRowEnd(self.text_area, offset)
        self.start = rowStart
        self.value = self.text_area.getText()[rowStart: rowEnd]

        self.text_area.getHighlighter().removeAllHighlights()
        painter = DefaultHighlighter.DefaultHighlightPainter(Color.LIGHT_GRAY)
        self.text_area.getHighlighter().addHighlight(rowStart, rowEnd, painter)



class ButtonHandlers:
    def __init__(self, text_field, text_area, mouse_listener, default_values):
        self.text_field = text_field
        self.text_area = text_area
        self.mouse_listener = mouse_listener
        self.default_values = default_values

    def handler_add(self, event):
        name = self.text_field.getText()
        self.text_area.append(name + os.linesep)
        self.text_field.setText('')

    def handler_rm(self, event):
        self.text_field.setText('')
        start, value = self.mouse_listener.getSelected()
        end = start + len(value)
        text_area = self.text_area.getText()
        text_area = (text_area[:start] + text_area[end:]).strip('\n').replace('\n\n', '\n')
        self.text_area.setText(text_area)

    def handler_restore(self, event):
        self.text_field.setText('')
        self.text_area.setText('')
        for name in self.default_values:
            self.text_area.append(name + os.linesep)
