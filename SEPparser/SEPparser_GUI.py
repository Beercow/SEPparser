import os
import sys
import re
import webbrowser
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
from ttkthemes import ThemedTk
import tkinter.font as tkFont
import json
import ctypes
import threading
import subprocess
import helpers.images as images

import msvcrt
from ctypes import windll, byref, wintypes, WinError
from ctypes.wintypes import HANDLE, LPDWORD, BOOL

__author__ = "Brian Maloney"
__version__ = "2022.12.21"
__email__ = "bmmaloney97@gmail.com"

PIPE_NOWAIT = wintypes.DWORD(0x00000001)

ERROR_NO_DATA = 232


def pipe_no_wait(pipefd):
    """ pipefd is a integer as returned by os.pipe """

    SetNamedPipeHandleState = windll.kernel32.SetNamedPipeHandleState
    SetNamedPipeHandleState.argtypes = [HANDLE, LPDWORD, LPDWORD, LPDWORD]
    SetNamedPipeHandleState.restype = BOOL

    h = msvcrt.get_osfhandle(pipefd)

    res = windll.kernel32.SetNamedPipeHandleState(h,
                                                  byref(PIPE_NOWAIT),
                                                  None,
                                                  None)
    if res == 0:
        print(WinError())
        return False
    return True


if getattr(sys, 'frozen', False):
    application_path = sys._MEIPASS
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

if os.path.isfile('SEPgui.settings'):
    with open("SEPgui.settings", "r") as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()
else:
    data = json.loads('{"theme": "vista", "directory": "", "file": "", "output": "", "registrationInfo": ""}')

settings = json.loads(r'{"v": "-d", "kapemode": "", "output": "", "path": "c:\\", "outpath": "", "append": "", "tvalue": 0, "tz": " ", "tzdata": "", "logging": "", "verbose": "", "e": "", "qd": "", "hd": "", "hf": "", "eb": "", "cmd": "", "i": "", "idata": ""}')

project = ''


class ToolTip(object):

    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.id = None
        self.x = self.y = 0

    def showtip(self, text):
        "Display text in tooltip window"
        self.text = text
        if str(self.widget['state']) == 'disable':
            return
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_pointerx()
        y = y + cy + self.widget.winfo_pointery() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        self.text = self.text.split('\n')
        textbox = tk.Text(tw, height=2, width=len(self.text[1]), padx=8,
                          pady=5, relief='raised')
        bold_font = tkFont.Font(textbox, textbox.cget("font"))
        bold_font.configure(weight="bold")
        textbox.tag_configure("bold", font=bold_font)
        textbox.insert('end', self.text[0] + '\n', 'bold')
        textbox.insert('end', self.text[1])
        textbox.configure(state='disable')
        textbox.grid(row=0, column=0)
        self.widget.after(5000, lambda: tw.destroy())

    def hidetip(self):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()


class quit:
    def __init__(self, root):
        self.root = root
        self.win = tk.Toplevel(self.root)
        self.win.attributes("-toolwindow", 1)
        self.win.attributes("-topmost", 1)
        self.win.title("Please confirm")
        self.win.grab_set()
        self.win.focus_force()
        self.win.resizable(False, False)
        self.win.protocol("WM_DELETE_WINDOW", self.__callback)

        self.frame = ttk.Frame(self.win)

        self.inner_frame = ttk.Frame(self.frame,
                                     relief='groove',
                                     padding=5)

        self.frame.grid(row=0, column=0)
        self.inner_frame.grid(row=0, column=0, padx=5, pady=5)

        self.label = ttk.Label(self.inner_frame,
                               text="Are you sure you want to exit?",
                               padding=5)

        self.yes = ttk.Button(self.inner_frame,
                              text="Yes",
                              takefocus=False,
                              command=lambda: self.btn1(root))

        self.no = ttk.Button(self.inner_frame,
                             text="No",
                             takefocus=False,
                             command=self.btn2)

        self.label.grid(row=0, column=0, columnspan=2)
        self.yes.grid(row=1, column=0, padx=5, pady=5)
        self.no.grid(row=1, column=1, padx=(0, 5), pady=5)

        self.sync_windows()

        self.root.bind('<Configure>', self.sync_windows)
        self.win.bind('<Configure>', self.sync_windows)

    def btn1(self, root):
        data['theme'] = ttk.Style().theme_use()
        with open("SEPgui.settings", "w") as jsonfile:
            json.dump(data, jsonfile)
        root.destroy()

    def btn2(self):
        self.root.unbind("<Configure>")
        self.win.destroy()

    def __callback(self):
        return

    def sync_windows(self, event=None):
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        self.win.geometry("+%d+%d" % (x + w/2, y + h/2))


class about:
    def __init__(self, root):
        self.root = root
        self.win = tk.Toplevel(self.root)
        self.win.title("About SEPparser GUI")
        self.win.attributes("-toolwindow", 1)
        self.win.attributes("-topmost", 1)
        self.win.grab_set()
        self.win.focus_force()
        self.win.resizable(False, False)
        self.win.protocol("WM_DELETE_WINDOW", self.btn)

        logo = images.logo()

        self.frame = ttk.Frame(self.win)
        self.inner_frame = ttk.Frame(self.frame, relief='groove', padding=5)
        self.frame.grid(row=0, column=0)
        self.inner_frame.grid(row=0, column=0, padx=5, pady=5)

        self.label = ttk.Label(self.inner_frame, image=logo, anchor='n')
        self.label.image = logo
        self.label1 = ttk.Label(self.inner_frame,
                                text="SEPparser GUI",
                                justify="left", anchor='w')
        self.label2 = ttk.Label(self.inner_frame,
                                text=f"Version {__version__}",
                                justify="left", anchor='w')
        self.label3 = ttk.Label(self.inner_frame,
                                text="Copyright © 2022",
                                justify="left", anchor='w')
        self.label4 = ttk.Label(self.inner_frame,
                                text="Brian Maloney",
                                justify="left", anchor='w')
        self.label5 = ttk.Label(self.inner_frame, text="L̲a̲t̲e̲s̲t̲_R̲e̲l̲e̲a̲s̲e̲",
                                foreground='#0563C1', cursor="hand2",
                                justify="left", anchor='w')
        self.text = tk.Text(self.inner_frame, width=27, height=8, wrap=tk.WORD)
        line = "GUI based application for parsing Symantec VBNs and telemitry data."
        self.text.insert(tk.END, line)
        self.text.config(state='disable')
        self.scrollbv = ttk.Scrollbar(self.inner_frame, orient="vertical",
                                      command=self.text.yview)
        self.text.configure(yscrollcommand=self.scrollbv.set)
        self.ok = ttk.Button(self.inner_frame,
                             text="OK",
                             padding=5,
                             command=self.btn)

        self.label.grid(row=0, column=0, rowspan=6,
                        padx=5, pady=(5, 0), sticky='n')
        self.label1.grid(row=0, column=1,
                         padx=(0, 5), pady=(5, 0), sticky="w")
        self.label2.grid(row=1, column=1, sticky="w")
        self.label3.grid(row=2, column=1, sticky="w")
        self.label4.grid(row=3, column=1, sticky="w")
        self.label5.grid(row=4, column=1,
                         padx=(0, 10), pady=(0, 10), sticky="w")
        self.text.grid(row=5, column=1, sticky='w')
        self.scrollbv.grid(row=5, column=2, padx=(0, 10), sticky="nsew")
        self.ok.grid(row=6, column=1, padx=(0, 5), pady=5, sticky="e")

        self.label5.bind("<Double-Button-1>", self.callback)
        self.sync_windows()

        self.root.bind("<Configure>", self.sync_windows)

    def btn(self):
        self.root.unbind("<Configure>")
        self.win.destroy()

    def sync_windows(self, event=None):
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        self.win.geometry("+%d+%d" % (x + w/2, y + h/2))

    def callback(self, event=None):
        webbrowser.open_new_tab("https://github.com/Beercow/SEPparser/releases/latest")
        self.label5.configure(foreground='#954F72')


def main():

    def CreateToolTip(widget, text):
        toolTip = ToolTip(widget)

        def enter(event):
            toolTip.showtip(text)

        def leave(event):
            toolTip.hidetip()
        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)
        widget.bind('<ButtonPress>', leave)

    def updtsettings():
        settings['v'] = f"{v.get()}"
        settings['kapemode'] = f"{kapemode.get()}"
        settings['output'] = f"{output.get()}"
        settings['path'] = f"{path.get()}"
        settings['outpath'] = f"{outpath.get()}"
        settings['append'] = f"{append.get()}"
        settings['tvalue'] = f"{tvalue.get()}"
        settings['tz'] = f"{tz.get()}"
        settings['tzdata'] = f"{tzdata.get()}"
        settings['logging'] = f"{logging.get()}"
        settings['verbose'] = f"{verbose.get()}"
        settings['e'] = f"{e.get()}"
        settings['qd'] = f"{qd.get()}"
        settings['hd'] = f"{hd.get()}"
        settings['hf'] = f"{hf.get()}"
        settings['eb'] = f"{eb.get()}"
        settings['cmd'] = f"{cmd.get()}"

    def check_expression(*args):
        outputtext.config(state=tk.NORMAL)
        updtsettings()
        varContent = v.get()

        if varContent == "-d":
            ent1['values'] = list(filter(None,
                                         sorted(data['directory'].split('|'))))
            cbx7.configure(state='disable')
            cbx9.configure(state='disable')
            cbx12.configure(state='disable')
            ent4.configure(state='disable')
            ent4.configure(cursor='arrow')
            hd.set("")
            e.set("")
            i.set("")
        else:
            ent1['values'] = list(filter(None,
                                         sorted(data['file'].split('|'))))
            cbx7.configure(state='normal')
            cbx9.configure(state='normal')
            cbx12.configure(state='normal')
        ent1.bind('<Button-1>',
                  lambda event=None,
                  e=ent1['values'],
                  n=250: on_combo_configure(e, n))
        pathContent = path.get()

        if output.get() == "-o":
            ent2.configure(state='normal')
            btn2.configure(state='normal')
        else:
            ent2.configure(state='disable')
            btn2.configure(state='disable')
            outpath.set('')
        ent2.bind('<Button-1>',
                  lambda event=None,
                  e=ent2['values'],
                  n=ent2.winfo_width(): on_combo_configure(e, n))

        # Optional arguments
        opt = ''
        if len(kapemode.get()) > 1:
            opt += f' {kapemode.get()}'
        if len(append.get()) > 1:
            opt += f' {append.get()}'
        if len(logging.get()) > 1:
            opt += f' {logging.get()}'
        if len(verbose.get()) > 1:
            opt += f' {verbose.get()}'
        if len(hd.get()) > 1:
            opt += f' {hd.get()}'
            if len(i.get()) > 1:
                opt += f' {i.get()}'
                ent4.configure(state='normal')
                ent4.configure(cursor='xterm')
            else:
                ent4.configure(state='disable')
                ent4.configure(cursor='arrow')
                idata.set("")
            if len(idata.get()) > 1:
                opt += f' {idata.get()}'
        if hd.get() == "-hd" or e.get() == "-e":
            cbx1.configure(state='disable')
            cbx2.configure(state='disable')
            cbx3.configure(state='disable')
            lbl1.configure(state='disable')
            cbx4.configure(state='disable')
            cbx8.configure(state='disable')
            cbx10.configure(state='disable')
            lbl4.configure(state='disable')
            cbx11.configure(state='disable')
            ent2.configure(state='disable')
            btn2.configure(state='disable')
            rbtn3.configure(state='disable')
            rbtn4.configure(state='disable')
            ent3.configure(state='disable')
            kapemode.set("")
            append.set("")
            qd.set("")
            hf.set("")
            eb.set("")
            output.set("")
            outpath.set('')
            tvalue.set(0)
            tz.set(' ')
            tzdata.set(' ')
        else:
            cbx1.configure(state='normal')
            cbx2.configure(state='normal')
            cbx3.configure(state='normal')
            lbl1.configure(state='normal')
            cbx4.configure(state='normal')
            cbx8.configure(state='normal')
            cbx10.configure(state='normal')
            cbx11.configure(state='normal')
            lbl4.configure(state='normal')
            ent4.configure(state='disable')
            ent4.configure(cursor='arrow')
            i.set("")
            idata.set("")
        if len(e.get()) > 1:
            opt += f' {e.get()}'
        if len(qd.get()) > 1:
            opt += f' {qd.get()}'
        if len(hf.get()) > 1:
            opt += f' {hf.get()}'
        if len(eb.get()) > 1:
            opt += f' {eb.get()}'
        if len(output.get()) > 1:
            opt += f' {output.get()}'
        if len(outpath.get()) > 0:
            opt += f' "{outpath.get()}"'
        if len(tz.get()) > 1:
            opt += f' {tz.get()}'
            if tz.get() == '-tz':
                btn.configure(state='disable')
                ent3['values'] = list(range(-12, 13))
                if len(tzdata.get()) > 0:
                    opt += f' {tzdata.get()}'
            else:
                btn.configure(state='normal')
                ent3['values'] = list(filter(None,
                                      sorted(data['registrationInfo'].split('|')
                                             )))
                if len(tzdata.get()) > 0:
                    opt += f' "{tzdata.get()}"'

            ent3.bind('<Button-1>',
                      lambda event=None,
                      e=ent3['values'],
                      n=ent3.winfo_width(): on_combo_configure(e, n))

        outputtext.delete(1.0, tk.END)  # clear the outputtext text widget
        outputtext.insert(tk.END, (f'SEPparser.exe {varContent} "{pathContent}"{opt}').replace('/', '\\'))
        outputtext.config(state='disable')
        cmd.set(f'{varContent} "{pathContent}"{opt}')

    def on_combo_configure(combo, n):
        test = max(combo, key=len)
        width = max(0,
                    tkFont.nametofont('TkTextFont').measure(test.strip() + '0')
                    - n)

        style = ttk.Style()
        style.configure('TCombobox', postoffset=(0, 0, width, 0))

    def callback():
        if v.get() == "-d":
            _ = filedialog.askdirectory(initialdir='C:/',
                                        title='Select Directory')
        else:
            _ = filedialog.askopenfilename(initialdir='C:/',
                                           title='Select File')
        path.set(_)
        check_expression()

    def callback2():
        if output.get() == "-o":
            _ = filedialog.askdirectory(initialdir='C:/',
                                        title='Select Directory')
        else:
            _ = ''
        outpath.set(_)
        check_expression()

    def callback3():
        _ = filedialog.askopenfilename(initialdir='C:/',
                                       title='Select File',
                                       initialfile='registrationInfo',
                                       defaultextension='xml',
                                       filetypes=[("Text files", "*.xml")])
        tzdata.set(_)
        check_expression()

    def tcheck():
        if tvalue.get() == 1:
            rbtn3.configure(state='normal')
            rbtn4.configure(state='normal')
            ent3.configure(state='normal')
            tz.set('-tz')
            CreateToolTip(ent3, text='Time Zone Offset\n'
                          '  Select UTC offset')
        else:
            rbtn3.configure(state='disable')
            rbtn4.configure(state='disable')
            ent3.configure(state='disable')
            btn.configure(state='disable')
            tz.set(' ')
            tzdata.set(' ')
        check_expression()

    def copy_command():
        cmd = outputtext.get('1.0', tk.END)
        root.clipboard_append(cmd[:-1])

    def execute():
        for widgets in tleft_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in tright_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in cleft_frame.winfo_children():
            widgets.configure(state='disable')
        for widgets in inner_frame.winfo_children():
            if ".!scrollbar" in str(widgets):
                pass
            else:
                widgets.configure(state='disable')
        menubar.entryconfig("File", state="disabled")
        menubar.entryconfig("Tools", state="disabled")
        menubar.entryconfig("Help", state="disabled")
        outputtext2.config(state='normal')
        outputtext2.delete('1.0', tk.END)
        if getattr(sys, 'frozen', False):
            cmdlist = "SEPparser.exe " + cmd.get()
        else:
            cmdlist = "py.exe SEPparser.py " + cmd.get()
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.Popen(cmdlist,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True,
                                startupinfo=startupinfo)
        ansi_escape = re.compile('((?:\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])){3}|(?:\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])){2}|(?:\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])))')
        pipe_no_wait(proc.stdout.fileno())
        pipe_no_wait(proc.stderr.fileno())

        while True:
            outputtext2.config(state='normal')
            try:
                line = proc.stderr.readline()

                if line == '':
                    pass

                else:
                    outputtext2.replace("end-2c linestart",
                                        "insert lineend",
                                        line)

                    outputtext2.see(tk.END)
                    continue

            except IOError:
                pass

            try:
                line = ansi_escape.split(proc.stdout.readline())

            except IOError:
                continue

            s = len(line)

            if s == 1:
                if line[0] == '':
                    break

                outputtext2.insert(tk.END, line[0])
                outputtext2.see(tk.END)
                continue

            if s % 2 != 0:
                s = s - 1

            outputtext2.insert(tk.END, line[0])
            outputtext2.see(tk.END)

            for i in range(1, s, 2):
                tag = line[i]
                w = line[i+1]

                outputtext2.insert(tk.END, w, tag)
                outputtext2.see(tk.END)

            if not line:
                break

            outputtext2.config(state='disable')

        outputtext2.config(state='disable')

        for widgets in tleft_frame.winfo_children():
            widgets.configure(state='normal')

        for widgets in cleft_frame.winfo_children():
            widgets.configure(state='normal')

        for widgets in inner_frame.winfo_children():
            if ".!scrollbar" in str(widgets):
                pass
            else:
                widgets.configure(state='normal')

        cbx2.configure(state='normal')
        cbx3.configure(state='normal')

        if output.get() == "-o":
            ent2.configure(state='normal')
            btn2.configure(state='normal')

        menubar.entryconfig("File", state="normal")
        menubar.entryconfig("Tools", state="normal")
        menubar.entryconfig("Help", state="normal")

        tcheck()

    def updtents():
        if v.get() == "-d":
            if path.get() not in data['directory'].split('|'):
                data['directory'] = f"{path.get()}|{data['directory']}"
                ent1['values'] = sorted(data['directory'].split('|'))
        else:
            if path.get() not in data['file'].split('|'):
                data['file'] = f"{path.get()}|{data['file']}"
                ent1['values'] = sorted(data['file'].split('|'))

        if outpath.get() not in data['output'].split('|'):
            data['output'] = f"{outpath.get()}|{data['output']}"
            ent2['values'] = sorted(data['output'].split('|'))

        if tz.get() == "-r":
            if tzdata.get() not in data['registrationInfo'].split('|'):
                data['registrationInfo'] = f"{tzdata.get()}|{data['registrationInfo']}"

    def menu_theme():
        s = ttk.Style()
        bg = s.lookup('TFrame', 'background')
        menubar.config(background=bg)
        tool_menu.config(bg=bg)

    def proj(menuitem):
        global project
        global settings

        if menuitem == "Open":
            filename = filedialog.askopenfilename(initialdir="/",
                                                  title=menuitem,
                                                  filetypes=(("SEPgui project files", "*.sep_proj"),))
            if filename:
                project = filename
                with open(project, "r") as jsonfile:
                    settings = json.load(jsonfile)
                jsonfile.close()

        if menuitem != "Open" and project == "" or menuitem == "Save As":
            filename = filedialog.asksaveasfilename(initialdir="/",
                                                    title=menuitem,
                                                    defaultextension=".sep_proj",
                                                    filetypes=(("SEPgui project files", "*.sep_proj"),))
            if filename:
                project = filename
                with open(project, "w") as jsonfile:
                    json.dump(settings, jsonfile)
                jsonfile.close()

        if project != "" and menuitem == "Save":
            with open(project, "w") as jsonfile:
                json.dump(settings, jsonfile)
            jsonfile.close()

        if menuitem == "Unload":
            settings = json.loads(r'{"v": "-d", "kapemode": "", "output": "", "path": "c:\\", "outpath": "", "append": "", "tvalue": 0, "tz": " ", "tzdata": "", "logging": "", "verbose": "", "e": "", "qd": "", "hd": "", "hf": "", "eb": "", "cmd": "", "i": "", "idata": ""}')
            project = ''
            pro_menu.entryconfig("Unload", state='disable')
            root.title('SEPparser GUI')

        if project:
            pro_menu.entryconfig("Unload", state="normal")
            proj_name = project.replace('/', '\\')
            root.title(f'SEPparser GUI | {proj_name}')

    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    root = ThemedTk()
    ttk.Style().theme_use(data['theme'])
    root.title(f'SEPparser GUI v{__version__}')
    root.iconbitmap(application_path + '/helpers/sep.ico')
#    root.tk.call('tk', 'scaling', 1)
    root.minsize(745, 400)
    root.protocol("WM_DELETE_WINDOW", lambda: quit(root))

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    menubar = tk.Menu(root)
    root.config(menu=menubar)

    file_menu = tk.Menu(menubar, tearoff=0)
    tool_menu = tk.Menu(menubar, tearoff=0)
    help_menu = tk.Menu(menubar, tearoff=0)
    submenu = tk.Menu(tool_menu, tearoff=0)
    pro_menu = tk.Menu(file_menu, tearoff=0)

    for theme_name in sorted(root.get_themes()):
        submenu.add_command(label=theme_name,
                            command=lambda t=theme_name: [submenu.entryconfig(submenu.index(ttk.Style().theme_use()), background=''),
                                                          root.set_theme(t),
                                                          submenu.entryconfig(submenu.index(ttk.Style().theme_use()), background='grey')])
    file_menu.add_cascade(label="Project", menu=pro_menu)
    file_menu.add_separator()
    file_menu.add_command(label="Exit",
                          command=lambda: quit(root))
    pro_menu.add_command(label="Load",
                         command=lambda: proj("Open"))
    pro_menu.add_command(label="Save",
                         command=lambda: proj("Save"),
                         accelerator="Ctrl+S")
    pro_menu.add_command(label="Save As",
                         command=lambda: proj("Save As"))
    pro_menu.add_command(label="Unload",
                         state='disable',
                         command=lambda: proj("Unload"))
    help_menu.add_command(label="About",
                          command=lambda: about(root))
    tool_menu.add_cascade(label="Skins",
                          menu=submenu)
    menubar.add_cascade(label="File",
                        menu=file_menu)
    menubar.add_cascade(label="Tools",
                        menu=tool_menu)
    menubar.add_cascade(label="Help",
                        menu=help_menu)
    submenu.entryconfig(submenu.index(ttk.Style().theme_use()),
                        background='grey')

    outer_frame = ttk.Frame(root)
    main_frame = ttk.Frame(outer_frame,
                           relief='groove',
                           padding=5)
    top_frame = ttk.Frame(main_frame)
    top_inner = ttk.Frame(top_frame)
    tleft_frame = ttk.LabelFrame(top_inner,
                                 text="Directory/Folder Input",
                                 padding=5)
    tright_frame = ttk.LabelFrame(top_inner,
                                  text="Output Options",
                                  padding=5)
    center_frame = ttk.Frame(main_frame,
                             padding=10)
    cleft_frame = ttk.LabelFrame(center_frame,
                                 text="Other Options",
                                 padding=5)
    cright_frame = ttk.LabelFrame(center_frame,
                                  text="SEPparser Output",
                                  padding=5)
    bottom_frame = ttk.Frame(main_frame)
    inner_frame = ttk.LabelFrame(bottom_frame,
                                 text="Current command line")

    outer_frame.grid(row=0, column=0, sticky="nsew")
    main_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
    top_frame.grid(row=0, column=0, sticky="ew")
    top_inner.grid(row=0, column=0, sticky="ew", padx=15, pady=(15, 0))
    tleft_frame.grid(row=0, column=0, sticky="ew")
    tright_frame.grid(row=0, column=1, sticky="ew", padx=10)
    center_frame.grid(row=1, column=0, sticky="nsew")
    cleft_frame.grid(row=0, column=0, sticky="ns", padx=5)
    cright_frame.grid(row=0, column=1, sticky="nsew", padx=5)
    bottom_frame.grid(row=2, column=0, sticky="ew")
    inner_frame.grid(row=0, column=0, sticky="ew", padx=15, pady=(0, 15))

    outer_frame.grid_rowconfigure(0, weight=1)
    outer_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_rowconfigure(1, weight=1)
    main_frame.grid_columnconfigure(0, weight=1)
    top_frame.grid_columnconfigure(0, weight=1)
    top_inner.grid_columnconfigure(0, weight=1)
    top_inner.grid_columnconfigure(1, weight=1)
    center_frame.grid_rowconfigure(0, weight=1)
    center_frame.grid_columnconfigure(1, weight=1)
    cright_frame.grid_rowconfigure(0, weight=1)
    cright_frame.grid_columnconfigure(0, weight=1)
    bottom_frame.grid_columnconfigure(0, weight=1)
    inner_frame.grid_columnconfigure(0, weight=1)

    v = tk.StringVar(value=settings['v'])
    kapemode = tk.StringVar(value=settings['kapemode'])
    output = tk.StringVar(value=settings['output'])
    path = tk.StringVar(value=settings['path'])
    path.trace_add('write', check_expression)
    outpath = tk.StringVar(value=settings['outpath'])
    outpath.trace_add('write', check_expression)
    append = tk.StringVar(value=settings['append'])
    tvalue = tk.IntVar(value=settings['tvalue'])
    tz = tk.StringVar(value=settings['tz'])
    tzdata = tk.StringVar(value=settings['tzdata'])
    tzdata.trace_add('write', check_expression)
    logging = tk.StringVar(value=settings['logging'])
    verbose = tk.StringVar(value=settings['verbose'])
    e = tk.StringVar(value=settings['e'])
    qd = tk.StringVar(value=settings['qd'])
    hd = tk.StringVar(value=settings['hd'])
    hf = tk.StringVar(value=settings['hf'])
    eb = tk.StringVar(value=settings['eb'])
    cmd = tk.StringVar(value=settings['cmd'])
    i = tk.StringVar(value=settings['i'])
    idata = tk.StringVar(value=settings['idata'])
    idata.trace_add('write', check_expression)

    rbtn1 = ttk.Radiobutton(tleft_frame,
                            text="Directory",
                            variable=v,
                            value="-d",
                            takefocus=False,
                            command=lambda: [path.set("c:\\"),
                                             check_expression])

    rbtn2 = ttk.Radiobutton(tleft_frame,
                            text="File",
                            variable=v,
                            value="-f",
                            takefocus=False,
                            command=lambda: [path.set("c:\\"),
                                             check_expression])

    ent1 = ttk.Combobox(tleft_frame,
                        width=38,
                        textvariable=path)

    btn1 = ttk.Button(tleft_frame,
                      text='...',
                      width=3,
                      takefocus=False,
                      command=lambda: callback())

    cbx1 = ttk.Checkbutton(tleft_frame,
                           text="Kape Mode",
                           offvalue="",
                           onvalue="-k",
                           var=kapemode,
                           takefocus=False,
                           command=check_expression)

    cbx2 = ttk.Checkbutton(tright_frame,
                           text="Output Directory",
                           offvalue="",
                           onvalue="-o",
                           var=output,
                           takefocus=False,
                           command=lambda: [outpath.set('.'),
                                            check_expression()])

    ent2 = ttk.Combobox(tright_frame,
                        width=38,
                        textvariable=outpath,
                        state='disable')

    ent2['values'] = list(filter(None, sorted(data['output'].split('|'))))

    btn2 = ttk.Button(tright_frame,
                      text='...',
                      width=3,
                      state='disable',
                      takefocus=False,
                      command=lambda: callback2())

    cbx3 = ttk.Checkbutton(tright_frame,
                           text="Append",
                           offvalue="",
                           onvalue="-a",
                           var=append,
                           takefocus=False,
                           command=check_expression)

    lbl1 = ttk.Label(cleft_frame,
                     text="Time Zone",
                     relief='groove',
                     padding=3)

    cbx4 = ttk.Checkbutton(cleft_frame,
                           offvalue=0,
                           onvalue=1,
                           var=tvalue,
                           takefocus=False,
                           command=tcheck)

    rbtn3 = ttk.Radiobutton(cleft_frame,
                            text="Offset",
                            variable=tz,
                            value="-tz",
                            state='disable',
                            takefocus=False,
                            command=lambda: [CreateToolTip(ent3,
                                                           text='Time Zone Offset\n'
                                                           '  Select UTC offset'),
                                             tzdata.set(''),
                                             check_expression])

    ent3 = ttk.Combobox(cleft_frame,
                        width=25,
                        state='disable',
                        textvariable=tzdata)

    btn = ttk.Button(cleft_frame,
                     text='...',
                     width=3,
                     state='disable',
                     takefocus=False,
                     command=lambda: callback3())

    rbtn4 = ttk.Radiobutton(cleft_frame,
                            text="registrationInfo.xml",
                            variable=tz,
                            value="-r",
                            state='disable',
                            takefocus=False,
                            command=lambda: [CreateToolTip(ent3,
                                                           text='registrationInfo.xml\n'
                                                           '  Path to registrationInfo.xml'),
                                             tzdata.set(''),
                                             check_expression])

    lbl2 = ttk.Label(cleft_frame,
                     text=" Logging",
                     relief='groove',
                     padding=3)

    cbx5 = ttk.Checkbutton(cleft_frame,
                           text="Enabled",
                           offvalue="",
                           onvalue="-l",
                           var=logging,
                           takefocus=False,
                           command=check_expression)

    cbx6 = ttk.Checkbutton(cleft_frame,
                           text="Verbose",
                           offvalue="",
                           onvalue="-v",
                           var=verbose,
                           takefocus=False,
                           command=check_expression)

    lbl3 = ttk.Label(cleft_frame,
                     text=" VBN Options",
                     relief='groove',
                     padding=3)

    cbx7 = ttk.Checkbutton(cleft_frame,
                           text="Extract",
                           offvalue="",
                           onvalue="-e",
                           state='disable',
                           var=e,
                           takefocus=False,
                           command=lambda: [hd.set(""), check_expression()])

    cbx8 = ttk.Checkbutton(cleft_frame,
                           text="Quarantine Dump",
                           offvalue="",
                           onvalue="-qd",
                           var=qd,
                           takefocus=False,
                           command=check_expression)

    cbx10 = ttk.Checkbutton(cleft_frame,
                            text="Hash File",
                            offvalue="",
                            onvalue="-hf",
                            var=hf,
                            takefocus=False,
                            command=check_expression)

    lbl4 = ttk.Label(cleft_frame,
                     text=" ccSubSDK",
                     relief='groove',
                     padding=3)

    cbx11 = ttk.Checkbutton(cleft_frame,
                            text="Extract Blob",
                            offvalue="",
                            onvalue="-eb",
                            var=eb,
                            takefocus=False,
                            command=check_expression)

    lbl5 = ttk.Label(cleft_frame,
                     text=" Research/Investigative",
                     relief='groove',
                     padding=3)

    cbx9 = ttk.Checkbutton(cleft_frame,
                           text="Hex Dump",
                           offvalue="",
                           onvalue="-hd",
                           state='disable',
                           var=hd,
                           takefocus=False,
                           command=lambda: [e.set(""),
                                            check_expression()])

    cbx12 = ttk.Checkbutton(cleft_frame,
                            text="submissions.idx index",
                            offvalue="",
                            onvalue="-i",
                            state='disable',
                            var=i,
                            takefocus=False,
                            command=lambda: [e.set(""),
                                             hd.set("-hd"),
                                             check_expression()])

    ent4 = ttk.Entry(cleft_frame,
                     width=8,
                     state='disable',
                     takefocus=False,
                     textvariable=idata)

    scrollb = ttk.Scrollbar(cright_frame)

    outputtext2 = tk.Text(cright_frame,
                          undo=False,
                          bg='black',
                          fg='light grey',
                          yscrollcommand=scrollb.set,
                          font=('Consolas', 12, 'normal'),
                          state='disable')

    outputtext2.tag_configure(b'\x1b[1;31m', foreground="red")
    outputtext2.tag_configure(b'\x1b[1;32m', foreground="green")
    outputtext2.tag_configure(b'\x1b[1;92m',
                              foreground="green",
                              font=('Consolas', 12, 'bold'))
    outputtext2.tag_configure(b'\x1b[1;33m', foreground="yellow")
    outputtext2.tag_configure(b'\x1b[1;93m',
                              foreground="yellow",
                              font=('Consolas', 12, 'bold'))
    outputtext2.tag_configure(b'\x1b[1;34m', foreground='#3B78FF')
    outputtext2.tag_configure(b'\x1b[1;35m', foreground="purple")
    outputtext2.tag_configure(b'\x1b[1;36m', foreground="cyan")
    outputtext2.tag_configure(b'\x1b[1;37m', foreground="white")
    outputtext2.tag_configure(b'\x1b[1;41m\x1b[1;37m',
                              background='#C50F1F')
    outputtext2.tag_configure(b'\x1b[1;42m\x1b[1;37m',
                              background='#13A10E')
    outputtext2.tag_configure(b'\x1b[1;43m\x1b[1;37m',
                              background='#C19C00')
    outputtext2.tag_configure(b'\x1b[1;44m\x1b[1;37m',
                              background='#0037DA')
    outputtext2.tag_configure(b'\x1b[1;45m\x1b[1;37m',
                              background='#881798')
    outputtext2.tag_configure(b'\x1b[1;46m\x1b[1;37m',
                              background='#3A96DD')
    outputtext2.tag_configure(b'\x1b[1;47m\x1b[1;30m',
                              background='#CCCCCC',
                              foreground='#767693')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;41m\x1b[1;37m',
                              background='#C50F1F')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;42m\x1b[1;37m',
                              background='#13A10E')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;43m\x1b[1;37m',
                              background='#C19C00')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;44m\x1b[1;37m',
                              background='#0037DA')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;45m\x1b[1;37m',
                              background='#881798')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;46m\x1b[1;37m',
                              background='#3A96DD')
    outputtext2.tag_configure(b'\x1b[1;0m\x1b[1;47m\x1b[1;30m',
                              background='#CCCCCC',
                              foreground='#767693')

    scrollb.config(command=outputtext2.yview)

    scrollb1 = ttk.Scrollbar(inner_frame)

    outputtext = tk.Text(inner_frame,
                         height=2,
                         yscrollcommand=scrollb1.set)

    scrollb1.config(command=outputtext.yview)

    check_expression()

    var = tk.IntVar()

    button2 = ttk.Button(inner_frame,
                         text="Execute!",
                         width=7,
                         takefocus=False,
                         command=lambda: [threading.Thread(target=execute,
                                                           daemon=True).start(),
                                          updtents()])

    button3 = ttk.Button(inner_frame,
                         text="Copy Command",
                         width=15,
                         takefocus=False,
                         command=lambda: copy_command())

    sg = ttk.Sizegrip(main_frame)

    rbtn1.grid(row=0, column=0)
    rbtn2.grid(row=0, column=1, padx=5)
    ent1.grid(row=0, column=2, padx=(0, 5))
    btn1.grid(row=0, column=3, padx=(0, 5))
    cbx1.grid(row=0, column=4)
    cbx2.grid(row=0, column=0)
    ent2.grid(row=0, column=1, padx=5)
    btn2.grid(row=0, column=2, padx=(0, 5))
    cbx3.grid(row=0, column=3)
    lbl1.grid(row=0, column=0, columnspan=2, sticky="nsew")
    cbx4.grid(row=0, column=1, sticky="w")
    rbtn3.grid(row=1, column=0, sticky="w", pady=5)
    rbtn4.grid(row=1, column=1, sticky="w", pady=5)
    ent3.grid(row=2, column=0, sticky="w", padx=(0, 5), pady=(0, 10))
    btn.grid(row=2, column=1, sticky="w", pady=(0, 10))
    lbl2.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=5)
    cbx5.grid(row=4, column=0, sticky="w", padx=(5, 0), pady=(0, 5))
    cbx6.grid(row=4, column=1, sticky="w", pady=(0, 5))
    lbl3.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=5)
    cbx7.grid(row=6, column=0, sticky="w", padx=5, pady=(0, 5))
    cbx8.grid(row=6, column=1, sticky="w")
    cbx10.grid(row=7, column=0, sticky="w", padx=5)
    lbl4.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=5)
    cbx11.grid(row=9, column=0, sticky="w", padx=5)
    lbl5.grid(row=10, column=0, columnspan=2, sticky="nsew", pady=5)
    cbx9.grid(row=11, column=0, sticky="w", padx=5, pady=(0, 5))
    cbx12.grid(row=12, column=0, sticky="w", padx=5, pady=(0, 5))
    ent4.grid(row=12, column=1, sticky="w")
    outputtext2.grid(row=0, column=0, columnspan=6, rowspan=10, sticky="nsew")
    scrollb.grid(row=0, column=6, rowspan=10, sticky="nsew")
    outputtext.grid(row=0, column=0, sticky="nsew", padx=(5, 0), pady=5)
    scrollb1.grid(row=0, column=1, sticky="nsew", padx=(0, 5), pady=5)
    button3.grid(row=1, sticky="w", padx=5, pady=5)
    button2.grid(row=1, columnspan=2, sticky="e", padx=5, pady=5)
    sg.grid(row=2, sticky='se')

    # Tool tips
    CreateToolTip(rbtn1, text='--dir\n'
                  '  Directory to run SEPparser against')
    CreateToolTip(rbtn2, text='--file\n'
                  '  File to run SEPparser against')
    CreateToolTip(ent1, text='Directory/File\n'
                  '  Path to directory or file to run SEPparser against')
    CreateToolTip(btn1, text='Select Directory/File\n'
                  '  Click to select directory or file')
    CreateToolTip(cbx1, text='--kape\n'
                  '  Check to use with KAPE or to scan for Symantec data')
    CreateToolTip(cbx2, text='--output\n'
                  '  Directory to output files to. Default is current directory.')
    CreateToolTip(ent2, text='Output\n'
                  '  Path to directory to save output to')
    CreateToolTip(btn2, text='Select Output Directory\n'
                  '  Click to select directory to save output to.')
    CreateToolTip(cbx3, text='--append\n'
                  '  Append parsed data to output files')
    CreateToolTip(cbx4, text='Change Time Zone\n'
                  '  Set time zone by offset or from registratInfo.xml file')
    CreateToolTip(rbtn3, text='--timezone\n'
                  '  UTC offset for time zone')
    CreateToolTip(rbtn4, text='--registrationInfo\n'
                  '  registrationInfo.xml file to get UTC offset from')
    CreateToolTip(btn, text='Select registrationInfo.xml\n'
                  '  Cick to select registrationInfo.xml file')
    CreateToolTip(cbx5, text='--log\n'
                  '  Save console output to log')
    CreateToolTip(cbx6, text='--verbose\n'
                  '  Display more verbose errors')
    CreateToolTip(cbx7, text='--extract\n'
                  '  Extract quarantine data from VBN if present')
    CreateToolTip(cbx8, text='--quarantine-dump\n'
                  '  Dump hex output of quarantine to screen')
    CreateToolTip(cbx9, text='--hex-dump\n'
                  '  Dump hex output of VBN to screen')
    CreateToolTip(cbx10, text='--hash-file\n'
                  '  Hash quarantine data to see if it matches recorded hash')
    CreateToolTip(cbx11, text='--extract-blob\n'
                  '  Extract potential binary blobs from ccSubSDK')
    CreateToolTip(button3, text='Copy command\n'
                  '  Copies the current command line to the clipboard')
    CreateToolTip(button2, text='Execute\n'
                  '  Click to execute the current command line')
    CreateToolTip(cbx12, text='--index\n'
                  '  Dump hex output of index in submissions.idx')
    CreateToolTip(ent4, text='Index Number\n'
                  '  Enter index number to hex dump from submissions.idx')

    root.bind('<Control-s>', lambda event=None, s="Save": proj(s))
    ent1.bind("<<ComboboxSelected>>", lambda event=None: ent1.select_clear())
    ent2.bind("<<ComboboxSelected>>", lambda event=None: ent2.select_clear())
    ent3.bind("<<ComboboxSelected>>", lambda event=None: ent3.select_clear())
    outputtext2.bind('<Key>', lambda a: "break")
    outputtext2.bind('<Button>', lambda a: "break")
    outputtext2.bind('<Motion>', lambda a: "break")

    root.mainloop()


if __name__ == '__main__':
    main()