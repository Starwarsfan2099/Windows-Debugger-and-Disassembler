# NOT READY FOR USE!!!!
import Tkinter as tk
import tkFileDialog
import os

root = tk.Tk()
root.title('PyPad')
root.geometry('800x800')

# Functions
def new_file(event=None):
	root.title('Untitled')
	global filename
	filename = None
	textPad.delete(1.0, tk.END)

def open_file(event=None):
	'''Open a text file '''

	global filename
	filename = tkFileDialog.askopenfilename(defaultextension='.txt',
											filetypes=[('All Files','*.*'),
											('Text Documents','*.txt')])
	# If no file chosen
	if filename == '':
		filename = None
	else:
		# Return the basename of 'file'
		root.title(os.path.basename(filename) + ' - PyPad')
		textPad.delete(1.0, tk.END)
		chosen_file = open(filename)
		textPad.insert(1.0, chosen_file.read())
		chosen_file.close()

def save_file(event=None):
	'''Save a file '''

	global filename

	try:
		f = open(filename, 'w')
		words = textPad.get(1.0, 'end')
		f.write(words)
		f.close()
	except:
		save_file_as()

def save_file_as(event=None):
	'''Save a file as you want '''

	try:
		f = tkFileDialog.asksaveasfilename(initialfile='Untitled.txt',
										   defaultextension='*.txt',
										   filetypes=[('All Files', '*.*'),
										   ('Text Documents', '*.txt')])
		fh = open(f, 'w')
		written_text = textPad.get(1.0, tk.END)
		fh.write(written_text)
		fh.close()
		root.title(os.path.basename(f) + ' - PyPad')
	except:
		pass

def exit_program(event=None):
	pass

def find_action():
	t2 = tk.Toplevel(root)
	t2.title('Find Text')
	t2.geometry('400x100')
	# Make sure the window is drawn on top of the root window with transient
	t2.transient(root)
	tk.Label(t2, text='Find All:').grid(row=0, column=0, sticky='e')
	v = tk.StringVar()
	search_phrase_box = tk.Entry(t2, width=25, textvariable=v)
	search_phrase_box.grid(row=0, column=1, padx=2, sticky='we')
	# Shift the cursor's focus to the new Entry widget
	search_phrase_box.focus_set()

	c = tk.IntVar()
	tk.Checkbutton(t2, text='Ignore Case', variable=c).grid(row=1, column=1,
				   sticky='e', padx=2, pady=2)
	tk.Button(t2, text='Find All', underline=0, command=lambda: search_for(v.get(), 
			  c.get(), textPad, t2, search_phrase_box)).grid(
			  row=0, column=2, sticky='e'+'w', padx=2, pady=2)
	def close_search():
		textPad.tag_remove('match', '1.0', tk.END)
		t2.destroy()
	# Override the close button
	t2.protocol('WM_DELETE_WINDOW', close_search)

def search_for(needle,cssnstv, textPad, t2,e) :
        textPad.tag_remove('match', '1.0', tk.END)
        count =0
        if needle:
                position = '1.0'
                while True:
                    position = textPad.search(needle, position, nocase=cssnstv, stopindex=tk.END)
                    if not position: break
                    lastposition = '%s+%dc' % (position, len(needle))
                    textPad.tag_add('match', position, lastposition)
                    count += 1
                    position = lastposition
                textPad.tag_config('match', foreground='yellow', background='#019875')
        e.focus_set()
        t2.title('%d found' % count)

def selectAll_action(event=None):
	textPad.tag_add('sel', '1.0', 'end')

# Built in Tkinter Event Generators
def undo_action():
	textPad.event_generate('<<Undo>>')
def redo_action():
	textPad.event_generate('<<Redo>>')
def cut_action():
	textPad.event_generate('<<Cut>>')
def copy_action():
	textPad.event_generate('<<Copy>>')
def paste_action():
	textPad.event_generate('<<Paste>>')

# Define your image icons
newicon = tk.PhotoImage(file='icons/newfile.gif')
openicon = tk.PhotoImage(file='icons/open.gif')
saveicon = tk.PhotoImage(file='icons/jesus.gif')
undoicon = tk.PhotoImage(file='icons/undo.gif')
redoicon = tk.PhotoImage(file='icons/redo.gif')
cuticon = tk.PhotoImage(file='icons/sting.gif')
copyicon = tk.PhotoImage(file='icons/copy.gif')
pasteicon = tk.PhotoImage(file='icons/paste.gif')

# Create a main row for the menu
menuBar = tk.Menu(root)
menuBar.add_cascade(label='PyPad')

# File Menu
fileMenu = tk.Menu(menuBar)
# Displays the column needed to see the add_commands
menuBar.add_cascade(label='File', menu=fileMenu)
fileMenu.add_command(label='New', accelerator='Command+N', compound=tk.LEFT,
					 image=newicon, underline=0, command=new_file)
fileMenu.add_command(label='Open', accelerator='Command+O', compound=tk.LEFT,
					 image=openicon, underline=0, command=open_file)
fileMenu.add_command(label='Save', accelerator='Command-S', compound=tk.LEFT,
					 image=saveicon, underline=0, command=save_file)
fileMenu.add_command(label='Save as', accelerator='Shift+Command+S', command=save_file_as)
fileMenu.add_separator()
fileMenu.add_command(label='Exit', accelerator='Command+W', command=exit_program)

# Edit menu
editMenu = tk.Menu(menuBar)
menuBar.add_cascade(label='Edit', menu=editMenu)
editMenu.add_command(label='Undo', accelerator='Command+Z', compound=tk.LEFT,
					image=undoicon, underline=0, command=undo_action)
editMenu.add_command(label='Redo', accelerator='Shift-Command+Z', compound=tk.LEFT,
					 image=redoicon, underline=0, command=redo_action)
editMenu.add_command(label='Cut', accelerator='Command+X', compound=tk.LEFT,
					 image=cuticon, underline=0, command=cut_action)
editMenu.add_command(label='Copy', accelerator='Command-C', compound=tk.LEFT,
					 image=copyicon, underline=0, command=copy_action)
editMenu.add_command(label='Paste', accelerator='Command+V', compound=tk.LEFT,
					 image=pasteicon, command=paste_action)
editMenu.add_separator()
editMenu.add_command(label='Find', accelerator='Command+F', underline=0, command=find_action)
editMenu.add_command(label='Select all', accelerator='Command+A', command=selectAll_action)

# View Menu
viewMenu = tk.Menu(menuBar)
menuBar.add_cascade(label='View', menu=viewMenu)
# Capture and create showLine, an instance of class IntVar
showLine = tk.IntVar()
# Set the initial value
showLine.set(1)
viewMenu.add_checkbutton(label='Show line number', variable=showLine)
showInBar = tk.IntVar()
showInBar.set(1)
viewMenu.add_checkbutton(label='Show info bar at bottom', variable = showInBar)
highlight = tk.IntVar()
viewMenu.add_checkbutton(label='Highlight current line', onvalue=1, offvalue=0, variable=highlight)
# A Theme Menu cascaded inside the view menu
themeMenu = tk.Menu(menuBar)
viewMenu.add_cascade(label='Themes', menu=themeMenu)
# Theme choices
themeSelection = {
'1. Default White': 'FFFFFF',
'2. Greygarious Grey':'D1D4D1',
'3. Lovely Lavender':'E1E1FF' , 
'4. Aquamarine': 'D1E7E0',
'5. Bold Beige': 'FFF0E1',
'6. Cobalt Blue':'333AA',
'7. Olive Green': '5B8340'
}
themeChoice = tk.StringVar()
themeChoice.set('1. Default White')
[themeMenu.add_radiobutton(label=i, variable=themeChoice) for i in sorted(themeSelection)]

# About Menu
aboutMenu = tk.Menu(menuBar)
menuBar.add_cascade(label='About', menu=aboutMenu)
aboutMenu.add_command(label='About')
aboutMenu.add_command(label='Help')

# The top shortcut bar
shortcutBar = tk.Frame(root, height=64, bg='#019875')
shortcutBar.pack(expand=tk.NO, fill=tk.X)

# Line label bar
# lineLabelBar = tk.Label(root, width=1, bg='black')
# lineLabelBar.pack(side=tk.LEFT, anchor='nw', fill=tk.Y)

# The text box
textPad = tk.Text(root, font='Helvetica', undo=True, selectforeground='White', selectbackground='#019875')
textPad.pack(expand=tk.YES, fill=tk.BOTH)

# The scroll bar, whose parent is textPad
scrollBar = tk.Scrollbar(textPad)
textPad.configure(yscrollcommand=scrollBar.set)
# need to dispaly the scroll bar
scrollBar.pack(side=tk.RIGHT, fill=tk.Y)

# Event Bindings for keyboard shortcuts
textPad.bind('<Command-A>', selectAll_action)
textPad.bind('<Command-a>', selectAll_action)
textPad.bind('<Command-N>', new_file)
textPad.bind('<Command-n>', new_file)
textPad.bind('<Command-W>', exit_program)
textPad.bind('<Command-w>', exit_program)
# Display the menu bar
root.config(menu=menuBar)
root.mainloop()
