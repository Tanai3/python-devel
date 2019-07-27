import tkinter as tk
from tkinter import *
from tkinter import ttk

class test_window(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.frame1 = tk.Frame(root)
        contents_list = []
        self.button1 = tk.Button(self.frame1, text="test1")
        self.button2 = tk.Button(self.frame1, text="test2")
        self.button3 = tk.Button(self.frame1, text="test3")
        self.button4 = tk.Button(self.frame1, text="test4")
        
        contents_list.append([self.button1, self.button2])
        contents_list.append([self.button3, self.button4])
        
        self.frame1.grid(row=0, column=0, sticky=N+S+E+W)
        for row_index in range(2):
            Grid.rowconfigure(self.frame1, row_index, weight=1)
            for column_index in range(2):
                Grid.columnconfigure(self.frame1, column_index, weight=1)
                contents_list[row_index][column_index].grid(row=row_index, column=column_index, sticky=N+S+E+W)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("test-window")
    Grid.rowconfigure(root, 0, weight=1)
    Grid.columnconfigure(root, 0, weight=1)
    root.geometry("640x480")
    test_window(root)
    root.mainloop()
    