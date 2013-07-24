#include 'slick.sh'
_menu _mdi_menu {
   submenu "&File","help file menu","Displays file menu","ncw" {
      "&New...","new","ncw","help file menu","Creates an empty file to edit";
      "New Item from &Template...","add-item","ncw","help Add New Item Dialog Box (Code Templates)","Create files from template";
      "&Open...\tF7","gui-open\tedit\te","ncw","help open dialog box","Opens a file for editing";
      "Open &URL...","open-url","","help Open URL dialog box","Opens an HTTP file";
      "&Close","quit\temacs-quit","","help file menu","Closes the current file";
      "Close All","close-all","","help file menu","Closes all files";
      "-","","","","";
      "&Save","save","","help file menu","Saves the current file";
      "Save &As...","gui-save-as","","help save as dialog box","Saves the current file under a different name";
      "Sav&e All","save-all","","help file menu","Saves all modified files";
      "&Revert","revert-or-refresh","","help file menu","Revert current file to version on disk";
      "Change &Directory...","gui-cd\tprompt-cd","ncw","help change directory dialog box","Changes the current working directory";
      "-","","","","";
      "&Backup history for ...","activate_deltasave","","","List backup information for ";
      "-","","","","";
      submenu "&FTP","help FTP Menu","Displays menu of FTP commands","ncw" {
         "&Start New Connection...","ftpOpen 1","","help FTP Menu","Activates FTP tool window and starts a new connection";
         "&Activate FTP","activate_ftp","","help FTP Menu","Activates FTP tool window";
         "&Upload","ftpUpload","","help FTP Menu","Uploads the current FTP file";
         "&Client","ftpClient","","help FTP Menu","Activates FTP Client toolbar";
         "&Profile Manager","ftpProfileManager","","help FTP Menu","Displays FTP Profile Manager dialog box";
         "Default Options...","ftp_default_options","","help FTP Menu","Displays FTP Options dialog box";
      }
      "-","","","","";
      "&Print...","gui-print","ncw","help Print Dialog Box","Prints current file or selection";
      "&Insert a File...","gui-insert-file\tget","nrdonly","help insert file dialog box","Inserts a file you choose at the cursor";
      "&Write Selection...","gui-write-selection\tput","sel","help write selection dialog box","Writes selected text to a file you choose";
      "Template Manager...","template-manager","ncw","help Template Manager Dialog Box (Code Templates)","Create, edit, and delete your templates";
      "Export to HTML...","export-html","ncw","help","Write file to HTML format";
      submenu "File &Manager","help file manager menu","Displays menu of file manager commands","ncw" {
         "&New File List...","fileman","ncw","help list files dialog box","Displays a directory of files you choose";
         "&Append File List...","fileman append","fileman","help list files dialog box","Appends files to current list";
         "S&ort...","fsort","fileman","help file sort dialog box","Sorts file list";
         "&Backup...","fileman-backup","fileman","help backup dialog box","Copies selected files and preserve directory structure";
         "&Copy...","fileman-copy","fileman","help copy dialog box","Copies selected files to a directory you choose";
         "&Move...","fileman-move","fileman","help move dialog box","Moves selected files to a directory you choose";
         "&Delete","fileman-delete","fileman","help file manager menu","Delete selected files";
         "&Edit","fileman-edit","fileman","help file manager menu","Edits selected files";
         submenu "&Select","help fileman select menu","Displays menu of file manager select commands","ncw" {
            "&All","fileman_select_all","fileman","help fileman select menu","Selects all files";
            "&Deselect All","deselect-all","fileman","help fileman select menu","Deselects all files";
            "&InvertSelect","select-reverse","fileman","help fileman select menu","Selects files which are not selected and deselects files which are selected";
            "A&ttribute...","select-attr","fileman","help fileman select menu","Selects files based on file attribute";
            "&Extension...","gui-select-ext","fileman","help fileman select menu","Selects files based on file extension";
            "&Highlight","select-mark","fileman","help fileman select menu","Selects files which are highlighted";
            "Dese&lect Highlight","deselect-mark","fileman","help fileman select menu","Deselects files which are highlighted";
         }
         submenu "&Files","help files menu","Displays menu of file manager listing commands","ncw" {
            "&Unlist All","unlist-all","fileman","help files menu","Removes all files from the list.  Files are not deleted.";
            "Unlist &Selected","unlist-select","fileman","help files menu","Removes selected files from the list.  Files are not deleted.";
            "Unlist &Extension...","gui-unlist-ext","fileman","help files menu","Removes files with a specific extension from the list";
            "Unlist &Attribute...","unlist-attr","fileman","help files menu","Removes files with a specific attribute from the list";
            "Unlist Sear&ch...","unlist-search","fileman","help unlist search dialog box","Removes lines which contain a particular search string";
            "&Read List...","read-list","fileman","help read list dialog box","Appends a list of files contained in a file";
            "&Write List...","write-list","fileman","help write list dialog box","Writes a file containing the currently selected files";
         }
         "A&ttribute...","fileman-attr","fileman","help file manager menu","Changes files attributes";
         "&Repeat Command...","for-select","fileman","help Repeat Command on Selected Dialog Box","Runs internal or external command on selected files";
         "&Global Replace...","fileman-replace","fileman","help global replace dialog box","Performs search and replace on selected files";
         "Global Find...","fileman-find","","help Global Find dialog","Performs search on selected files";
      }
      "-","","","","";
      "E&xit","safe-exit","ncw","help file menu","Prompts you to save files if necessary and exits the editor";
   }
   submenu "&Edit","help edit menu","Displays edit menu","ncw" {
      "&Undo","undo","undo|nicon|nrdonly","help edit menu","Undoes the last edit operation";
      "&Redo","redo","nicon|nrdonly","help edit menu","Undoes an undo operation";
      "Multi-File Undo","mfundo","","help edit menu","Undoes the last multi file operation";
      "Multi-File Redo","mfredo","","help edit menu","Undoes a multi file undo operation";
      "-","","","","";
      "Cu&t","cut","sel|nrdonly","help edit menu","Deletes the selected text and copies it to the clipboard";
      "&Copy","copy-to-clipboard","ab-sel|nicon","help edit menu","Copies the selected text to the clipboard";
      "&Paste","paste\tbrief-paste\temacs-paste","clipboard|nicon|nrdonly","help edit menu","Inserts the clipboard into the current file";
      "&List Clipboards...\tCtrl+X Ctrl+Y","list-clipboards","nicon|nrdonly","help list clipboards dialog box","Inserts a clipboard selected from a list of your recently created clipboards";
      "Copy &Word","copy-word","nicon","help edit menu","Copies the current word to the clipboard";
      "&Append to Clipboard","append-to-clipboard","ab-sel|nicon","help edit menu","Appends the selected text to the clipboard";
      "App&end Cut","append-cut","ab-sel|nicon|nrdonly","help edit menu","Deletes the selected text and appends it to the clipboard";
      "Insert Literal...","insert-literal","nicon|nrdonly","help insert literal dialog box","Inserts a character code you specify";
      "-","","","","";
      submenu "&Select","help edit select menu","Displays menu for selecting and deselecting text","ncw" {
         "C&har","select-char","nicon","help edit select menu","Starts or ends a character/stream selection";
         "&Block","select-block","nicon","help edit select menu","Starts or ends a block/column selection";
         "&Line","select-line","nicon","help edit select menu","Starts or ends a line selection";
         "&Word","select-whole-word","","help edit select menu","Selects the word under cursor";
         "&Code Block","select-code-block","","help edit select menu","Selects current code block";
         "&Procedure","select-proc","nicon","help edit select menu","Selects procedure/function";
         "&Deselect","deselect","sel","help edit select menu","Unhighlights selected text";
         "&All","select-all","","help edit select menu","Select all text in current buffer";
      }
      submenu "&Delete","help delete menu","Displays menu for deleting text","ncw" {
         "&Word","cut-full-word","nicon|nrdonly","help delete menu","Deletes text from the cursor to the end of the current word and copies it to the clipboard";
         "&Line","cut-line","nicon|nrdonly","help delete menu","Deletes the current line and copies it to the clipboard";
         "&To End of Line","cut-end-line","nicon|nrdonly","help delete menu","Deletes text from the cursor to the end of the line and copies it to the clipboard";
         "&Selection","delete-selection","sel|nicon|nrdonly","help delete menu","Deletes the selected text";
         "&All","delete-all","","help delete menu","Delete all text in current buffer";
      }
      "Complete Previous Word","complete-prev","nrdonly","help Edit Menu","Retrieves previous word or variable matching word prefix at cursor";
      "Complete Next Word","complete-next","nrdonly","help Edit Menu","Retrieves next word or variable matching word prefix at cursor";
      "&Fill...","gui-fill-selection\tfill-selection","sel|nicon|nrdonly","help edit menu","Fills the selected text with a character you choose";
      "&Indent","indent-selection","sel|nicon|nrdonly","help edit menu","Indents the selected text based on the tabs or indent for each level";
      "U&nindent","unindent-selection","sel|nicon|nrdonly","help edit menu","Unindents the selected text based on the tabs or indent for each level";
      submenu "&Other","help edit other menu","Displays menu containing more edit related commands","ncw" {
         "&Lowcase","lowcase-selection","sel|nicon|nrdonly","help edit other menu","Translates the characters in the selection or current word to lower case";
         "&Upcase","upcase-selection","sel|nicon|nrdonly","help edit other menu","Translates the characters in the selection or current word to upper case";
         "Cap&italize","cap-selection","sel|nicon|nrdonly","help edit other menu","Capitalizes the first character of each word in the current selection";
         "-","","","","";
         "&Shift Left","shift-selection-left","sel|nicon|nrdonly","help edit other menu","Deletes the first column of text in each line of the selected text";
         "Shift &Right","shift-selection-right","sel|nicon|nrdonly","help edit other menu","Inserts a space at the first column of each line of the selected text";
         "&Overlay Block","overlay-block-selection","block|nicon|nrdonly","help edit other menu","Overwrites selected block/column of text at the cursor";
         "&Adjust Block","adjust-block-selection","block|nicon|nrdonly","help edit other menu","Overlays the selected text at the cursor and fills the original selected text with spaces";
         "&Enumerate...","gui-enumerate","ab-sel","help Edit Other Menu","Adds incrementing numbers to a selection";
         "&Filter Selection...","filter_command","","","Filter the selected text through an external command";
         "-","","","","";
         "Copy UC&N As Unicode","copy_ucn_as_unicode","","help edit other menu",'Copies various UCN forms (like \uHHHH, \xHHHH, &#xHHHH etc.) as Unicode';
         submenu "&Copy Unicode As","help edit other copy unicode as ucn menu","Displays menu containing copy as Unicode commands","ncw" {
            '&C++ (UTF-16 \xHHHH)',"copy-unicode-as-c","","help Copy Unicode As menu",'Copies unicode characters in selection as C++ UTF-16 \xHHHH notation';
            '&Regex (UTF-32 \x{HHHH})',"copy-unicode-as-regex","","help Copy Unicode As menu",'Copies unicode characters in selection as Regex UTF-32 \x{HHHH} notation';
            '&Java/C# (UTF-16 \uHHHH)',"copy-unicode-as-java","","help Copy Unicode As menu",'Copies unicode characters in selection as Java/C# UTF-16 \uHHHH notation';
            '&UCN (UTF-32 \uHHHH and \UHHHHHHHH)',"copy-unicode-as-ucn","","help Copy Unicode As menu",'Copies unicode characters in selection as UCN \uHHHH and \UHHHHHHHH UTF-32 notation';
            "SGML/XML &hexadecimal (UTF-32 &&#xHHHH;)","copy-unicode-as-xml","","help Copy Unicode As menu","Copies unicode characters in selection as SGML/XML &#xHHHH; UTF-32 notation";
            "SGML/XML &decimal (UTF-32 &&#DDDD;)","copy-unicode-as-xmldec","","help Copy Unicode As menu","Copies unicode characters in selection as SGML/XML &#DDDD; UTF-32 notation";
         }
         "-","","","","";
         "&Tabs to Spaces","convert_tabs2spaces","nicon|nrdonly","help edit other menu","Converts tabs to spaces for selection or current buffer";
         "S&paces to Tabs","convert_spaces2tabs","","help edit other menu","Converts indentation spaces to tabs for selection or current buffer";
         "Remove Trailing &Whitespace","remove_trailing_spaces","","help edit other menu","Removes whitespace spaces at end of line";
         "&Block Insert Mode","block_insert_mode","","help Edit Other menu","Allows you to insert/delete characters for an entire block/column selection";
      }
   }
   submenu "&Search","help search menu","Displays menu of search commands","ncw" {
      "&Find...","gui-find\t/\tl\tsearch-forward","ncw","help Find and Replace tool window","Searches for a string you specify";
      "F&ind in Files...","find-in-files","ncw","help Find and Replace tool window","Searches for a string in files";
      "&Next Occurrence","find-next\tsearch-again","ncw","help search menu","Searches for the next occurrence of the last string you searched for";
      "&Previous Occurrence","find-prev\tsearch-again","ncw","help search menu","Searches for the previous occurrence of the last string you searched for";
      "&Replace...","gui-replace\tc\ttranslate-forward\tquery-replace","ncw","help Find and Replace tool window","Searches for a string and replaces it with another string";
      "R&eplace in Files...","replace-in-files","ncw","help Find and Replace tool window","Searches for a string and replaces it with another string in files";
      "Incremental Search","i-search","","help Incremental Searching","Searches for match incrementally";
      "Find File...","find-file","","help find file dialog box","Searches for files on disk";
      "Find S&ymbol...","activate-find-symbol\tgui-push-tag","ncw","help Find Symbol tool window","Searches tag databases for a symbol you specify";
      "-","","","","";
      "&Go to Line...","gui-goto-line\tgoto-line","nicon","help search menu","Places the cursor on a line you specify";
      "Go to Col&umn...","gui-goto-col","","help search menu","Places the cursor on a column you specify";
      "Go to &Offset...","gui-seek","nicon","help Seek dialog","Places the cursor on a byte/character offset in the current file";
      "Go to &Matching &Parenthesis\tCtrl+]","find-matching-paren","nicon","help Begin End Structure Matching","Finds the matching parenthesis or begin/end structure pair";
      "Go to &Definition","push-tag","ncw","help Go to definition","Goes to definition or declaration for word at cursor";
      "Go to Referen&ce","push-ref","ncw","help Go to reference","Search for references to the symbol under the cursor";
      "-","","","","";
      submenu "&Bookmarks","help bookmarks menu","Displays Bookmark-related menu items","ncw" {
         "P&ush Bookmark","push-bookmark","nicon","help bookmarks","Pushes a bookmark at the cursor";
         "P&op Bookmark","pop-bookmark","","help bookmarks","Pops the last bookmark";
         "Bookmark Stac&k...","bookmark-stack","","help Bookmark Stack dialog","Displays all pushed bookmarks";
         "&Set Bookmark...","set-bookmark","ncw","help bookmarks","Set a persistent bookmark on the current line";
         "Go to Bookmark...","goto-bookmark","ncw","help Go to Bookmark dialog box","Displays Go to Bookmark dialog box";
         "&Toggle Bookmark","toggle-bookmark","toggle_bookmark","help bookmarks","Toggles setting a bookmark on the current line";
         "&Bookmarks Tool Window...","activate-bookmarks","ncw","help Bookmarks Tool Window","List bookmarks and allows you to add and delete bookmarks";
         "Ne&xt Bookmark","next-bookmark","ncs","help bookmarks","Go to next bookmark";
         "Pre&vious Bookmark","prev-bookmark","ncs","help bookmarks","Go to previous bookmark";
      }
      "-","","","","";
      "&Last Find/Grep List","grep_last","ncw","help search menu","Displays list of Files/Buffers generated by Find command";
   }
   submenu "&View","help view menu","Displays view menu","ncw" {
      "&Hex","hex","","help view menu","Toggles hex/ASCII display";
      "Line Hex","linehex","","help view menu","Toggles line hex/ASCII display";
      "S&pecial Chars","view-specialchars-toggle","","help view menu","Toggles viewing of tabs,spaces, and new line character(s) on/off";
      "&New Line Chars","view-nlchars-toggle","","help view menu","Toggles viewing of new line character(s) on/off";
      "Ta&b Chars","view-tabs-toggle","","help View Menu","Toggles viewing of tab character(s) on/off";
      "Spac&es","view-spaces-toggle","","help View Menu","Toggles viewing of space character(s) on/off";
      "&Line Numbers","view-line-numbers-toggle","","help view menu","Toggles viewing of line numbers on/off";
      "-","","","","";
      "Soft &Wrap","softwrap-toggle","","help view menu","Toggles wrapping of long lines to window width";
      "Language &View Options... ","setupext -view","","help View Options (Language Specific)","Configure default view options for current language";
      "-","","","","";
      submenu "&Toolbars","","Show, hide, or customize a toolbar","ncw" {
         "Customize...","toolbars","","help Toolbar Customization dialog","";
      }
      submenu "&Tool Windows","","Show, hide, or customize a tool window","ncw" {
         "Customize...","customize_tool_windows","","help Toolbar Customization dialog","";
      }
      "F&ull Screen","fullscreen","","help Full Screen Mode","Toggles full screen editing mode";
      "-","","","","";
      "&Selective Display...","selective-display","","help Selective Display dialog box","Allows you to hide lines and create an outline";
      "Hide All Co&mments","hide-all-comments","","help View menu","Hides all lines that only contain a comment";
      "Hide &Code Block","hide-code-block","","help View menu","Hides lines inside current code block";
      "Hi&de Selection","hide-selection","sel","help View menu","Hides selected lines";
      "Hide #&region Blocks","hide-dotnet-regions","","help View menu","Hides .NET #region blocks";
      "&Function Headings","show-procs","","help View menu","Collapses all function code blocks in the current file";
      "E&xpand/Collapse Block","plusminus","","help View menu","Toggles between hiding and showing the code block under the cursor";
      "Copy &Visible","copy-selective-display","","help View menu","Copies text not hidden by selective display";
      "Show &All","show-all","","help view menu","Ends selective display.  All lines are displayed and outline bitmaps are removed";
   }
   submenu "&Project","help project menu","Displays project menu","ncw" {
      "&New...","project_new_maybe_wizard","ncw","help New Project Tab","Allows you to create a workspace and/or project";
      "&Open Workspace...","workspace-open","ncw","help Project Menu","Opens a workspace";
      submenu "Open O&ther Workspace","","Opens a workspace","ncw" {
         "Visual Studio .NET &Solution...","workspace_open_visualstudio","","help Open Other Workspace Menu","Open a Visual Studio Solution";
         "Visual &C++ Workspace...","workspace_open_visualcpp","","help Open Other Workspace Menu","Open a Visual C++ Workspace";
         "Visual C++ E&mbedded Workspace...","workspace_open_visualcppembedded","","help Open Other Workspace Menu","Open a Visual C++ Embedded Workspace";
         "&Tornado Workspace...","workspace_open_tornado","","help Open Other Workspace Menu","Open a Tornado Workspace";
         "&Ant XML Build File...","workspace_open_ant","","help Open Other Workspace Menu","Open an Ant XML Build File";
         "&Makefile...","workspace_open_makefile","","help Open Other Workspace Menu","Open a Makefile";
         "&QT Makefile...","workspace_open_qtmakefile","","help Open Other Workspace Menu","Open a QT Makefile";
         "&NAnt .build File...","workspace_open_nant","","help Open Other Workspace Menu","Open a NAnt .build file";
         "&JBuilder Project...","workspace_open_jbuilder","","help Open Other Workspace Menu","Open a JBuilder Project";
         "&Xcode Project...","workspace_open_xcode","","help Open Other Workspace Menu","Open a Xcode Project";
         "&Flash Project...","workspace_open_flash","","help Open Other Workspace Menu","Open a Flash Project";
         "-","","","","";
         "Workspace from C&VS...","cvs-open-workspace","","help Open Other Workspace Menu","Checkout and open a workspace from CVS";
         "Convert Co&deWright Workspace","cwprojconv.e","","help Open Other Workspace Menu","Convert a Codewright workspace and projects to SlickEdit workspace and projects";
      }
      "&Close Workspace","workspace-close","ncw","help project menu","Closes the current workspace";
      "Or&ganize All Workspaces...","workspace-organize","","help Managing Workspaces","Manage workspaces";
      "&Workspace Properties...","workspace_properties","","help Workspace Properties dialog","Lists projects in the current workspace";
      "Re&tag Workspace...","workspace_retag","","help Rebuilding Tag Files","Rebuilds the tag file for the current workspace";
      "&Refresh","workspace_refresh","","help Managing Workspaces","Refreshes current workspace, projects, and tag files";
      "-","","","","";
      "Add New Item from Template...","project-add-item","ncw","help Add New Item Dialog Box (Code Templates)","Create files from template and add to project";
      "-","","","","";
      "Open &Files from Project...","project-load -p","ncw","help project menu","Open files from current project";
      "Open Files from Workspace...","project-load","ncw","help project menu","Open files from current workspace";
      "&Insert Project into Workspace...","workspace_insert","","help Project Menu","Adds an existing project to the current workspace";
      "&Dependencies...","workspace_dependencies","","help dependencies (defining for projects)","Sets the dependencies for the active project";
      "Project Prop&erties...","project-edit","ncw","help Project Properties dialog","Edit settings for the current project";
   }
   submenu "&Build","help project menu","Displays project menu","ncw" {
      "-","-","","","";
      "&Next Error","next-error","ncw","help build menu","Processes the next compiler error message";
      "&Previous Error","prev-error","ncw","help build menu","Processes the previous compiler error message";
      "&Go to Error or Include","cursor-error","nicon","help build menu","Parses the error message or filename at the cursor and places cursor in file";
      "&Clear All Error Markers","clear-all-error-markers","ncw","help build menu","Removes all error markers in all files";
      "Configure Error Parsing...","configure-error-regex","ncw","help Error Regular Expressions dialog box","Configures regular expressions used to search for compiler messages";
      "-","","","","";
      "&Stop Build","stop-process","ncw","help build menu","Sends break signal to the build tab";
      "Show Build","start-process","ncw","help build menu","Starts or activates the the build tab";
      "Build Automatically on Save","project-toggle-auto-build","ncw","help build menu","Toggles option to build projects automatically on file save";
   }
   submenu "&Debug","help debug menu","Displays debug menu","ncw" {
      submenu "Windows","help Debug Windows menu","Displays debug window toolbars","" {
         "&Call Stack","activate_call_stack","","help Debug Windows menu","Activates the Call Stack window";
         "&Locals","activate-locals","","help Debug Windows menu","Activates the Locals window";
         "&Members","activate-members","","help Debug Windows menu","Activates the window which displays member variables";
         "&Autos","activate-autos","","help Debug Windows menu","Activates the Autos window";
         "&Watch","activate-watch","","help Debug Windows menu","Activates the Watch window";
         "T&hreads","activate-threads","","help Debug Windows menu","Activates the Threads window";
         "&Breakpoints","activate-breakpoints","","help Debug Windows menu","Activates the Breakpoints window";
         "&Registers","activate-registers","","help Debug Windows menu","Activates the Registers window";
         "Memo&ry","activate-memory","","help Debug Windows menu","Activates the Memory window";
         "Loaded &Classes","activate-classes","","help Debug Windows menu","Activates the Loaded Classes window";
      }
      "&Start","project_debug","","help debug menu","Starts debugger";
      "Suspend","debug_suspend","","help debug menu","Suspends execution";
      "Stop &Debugging","debug_stop","","help debug menu","Stops debugging the program";
      "&Restart","debug_restart","","help debug menu","Restarts the program";
      "-","","","","";
      submenu "&Attach Debugger","help Attach Debugger Menu","Attach debugger to a process, remote server or core file","" {
         "Attach to Running Process...","debug_attach gdb","","help Attach Debugger menu","Attach debugger to a running process using GDB";
         "Analyze Core File...","debug_corefile gdb","","help Attach Debugger menu","Attach debugger to a core file";
         "Attach to Remote Process...","debug_remote gdb","","help Attach Debugger menu","Attach debugger to a remote GDB server or executable with GDB stub";
         "&Attach to Java Virtual Machine...","debug_attach jdwp","","help Attach Debugger menu","Attach to a Java virtual machine executing remotely";
         "Attach to &Xdebug...","debug_remote xdebug","","help Attach Debugger menu","Listen for a remote connection from Xdebug";
         "Attach to &pydbgp...","debug_remote pydbgp","","help Attach Debugger menu","Listen for a remote connection from pydbgp (Python)";
         "Attach to &perl5db...","debug_remote perl5db","","help Attach Debugger menu","Listen for a remote connection from perl5db (Perl)";
         "Attach to &rdbgp...","debug_remote rdbgp","","help Attach Debugger menu","Listen for a remote connection from rdbgp (Ruby)";
         "Debug Other Executable...","debug_executable gdb","","help Attach Debugger menu","Step into to a program using GDB";
      }
      "Detach","debug_detach","","help debug menu","Detach from target process and allow application to continue running";
      "Debugger Information...","debug_props","","help Debugger Information dialog","Displays the debugger information dialog";
      "-","","","","";
      "Step &Into","debug_step_into","","help debug menu","Steps into the next statement";
      "Step &Over","debug_step_over","","help debug menu","Steps over the next statement";
      "Step Ou&t","debug_step_out","","help debug menu","Steps out of the current function";
      "Step Instruction","debug_step_instr","","help debug menu","Steps by one instruction";
      "-","","","","";
      "&Run to Cursor","debug-run-to-cursor","","help debug menu","Runs the program to the line containing the cursor";
      "Show &Next Statement","debug_show_next_statement","","help debug menu","Displays the source line for the instruction pointer";
      "Set Instruction Pointer","debug_set_instruction_pointer","","help debug menu","Set the instruction pointer to the current line";
      "Show Disassembly","debug_toggle_disassembly","","help debug menu","Toggle display of disassembly";
      "-","","","","";
      "Toggle Breakpoint","debug_toggle_breakpoint","","","";
      "Delete All Breakpoints","debug_clear_all_breakpoints","","help debug menu","Deletes all debugger breakpoints";
      "Disable All Breakpoints","debug_disable_all_breakpoints","","help debug menu","Disables all debugger breakpoints";
      "Add Watch","debug_add_watch","","help debug menu","Add a watch on the variable under the cursor";
      "Set Watchpoint","debug_add_watchpoint","","help debug menu","Set a watchpoint on the variable under the cursor";
      "-","","","","";
      "Debugger &Options...","debug_options","","help Debugger Options","Displays the Debugger Options dialog";
   }
   submenu "Do&cument","help document menu","Displays document menu","ncw" {
      "&Next Buffer","next-buffer","mto-buffer","help Document Menu","Switches to the next buffer";
      "Pre&vious Buffer","prev-buffer","mto-buffer","help Document Menu","Switches to the previous buffer";
      "Close Buffer","close-buffer","","help Document Menu","Closes the current buffer";
      "&List Open Files...","list-buffers","ncw","help Files tool window","List all buffers and allows you to activate one";
      "Edit Associated File","edit-associated-file","ncw","help Document Menu","Switch to header or source file associated with the current file";
      "Select Mo&de...","select-mode","","help Select Mode dialog box","List all modes and lets you select one";
      "Language &Options...","setupext","","help Language Options","Control the behavior of SlickEdit when working with this language";
      "-","","","","";
      "&Tabs...","gui-tabs","nrdonly","help Tabs dialog box","Sets tab stops";
      "&Margins...","gui-margins","nrdonly","help document menu","Sets margins";
      "-","","","","";
      "Format &Paragraph","reflow-paragraph","nicon|nrdonly","help document menu","Reflows the text in the current paragraph according to the margins";
      "Format &Selection","reflow-selection","sel|nicon|nrdonly","help document menu","Reflows the selected text according to the margins";
      "Format Columns","format-columns","ab-sel|nicon|nrdonly","help document menu","Format columns according to words";
      "-","","","","";
      "Edit &Javadoc Comment","javadoc-editor","","help Javadoc Editor dialog box","Edits Javadoc comments for the current source file";
      "Comment &Block","box","ab-sel|nrdonly","help Comments","Converts selected text into block comment using box comment setup characters";
      "Comment Lines","comment","ab-sel|nrdonly","help Comments","Converts selected lines into line comments using the line comment setup";
      "Uncomment Lines","comment_erase","ab-sel|nrdonly","help Comments","Uncomment selected lines using comment setup";
      "Re&flow Comment...","gui-reflow-comment","nrdonly","help Reflowing Comments","Reflows and reformats the current block comment";
      "Comment Setup...","comment-setup","","help Comment Options (Language-Specific)","Displays settings for box and line comments";
      "&Comment Wrap","comment-wrap-toggle","nrdonly","help Comment Wrap Options (Language-Specific)","Toggles comment wrap on/off";
      submenu "&XML/HTML Formatting","help XML/HTML formatting menu","Displays menu of XML/HTML formatting commands","" {
         "Current Document Options...","xml_html_document_options","ncw","Current Document Options dialog","Displays XML/HTML Formatting options for the current buffer";
         "-","","","","";
         "Enable XML/HTML Formatting","XW_formatting_toggle","nrdonly","help XML/HTML formatting menu","Toggles XML Formatting on/off";
         "Content Wrap","XW_contentwrap_toggle","nrdonly","help XML/HTML formatting menu","Toggles XML Content Wrap on/off";
         "Tag Layout","XW_taglayout_toggle","nrdonly","help XML/HTML formatting menu","Toggles XML Tag Layout on/off";
      }
      "-","","","","";
      "&Indent with Tabs","indent-with-tabs-toggle","nrdonly","help document menu","Toggles indenting with tabs on/off";
      "&Word Wrap","word-wrap-toggle","nrdonly","help document menu","Toggles word wrap on/off";
      "&Justify...","gui-justify","nrdonly","help justification dialog box","Sets/displays paragraph justification style";
      "&Read Only Mode","read-only-mode-toggle","","help document menu","Toggles Read only mode on/off";
      "&Adaptive Formatting","adaptive-format-toggle","","","Toggles adaptive formatting on/off";
   }
   submenu "&Macro","help macro menu","Displays menu of macro programming commands","ncw" {
      "Loa&d Module...","gui-load\tload\tprompt-load","ncw","help load module dialog box","Loads a macro source module";
      "&Unload Module...","gui-unload\tunload","ncw","help macro menu","Unloads a macro module";
      "List User-Loaded Modules...","gui-list-macfiles","ncw","help macro menu","List user-loaded Slick-C® modules";
      "-","","","","";
      "&Record Macro","record-macro-toggle","nicon","help macro menu","Starts recording Slick-C® language macro based on the editor features you use";
      "E&xecute last-macro","record-macro-end-execute\tlast-macro","nicon","help macro menu","Runs last recorded macro";
      "&Save last-macro...","gui-save-macro\tsave-macro","","help save macro dialog box","Saves the last recorded macro under a name you specify";
      "&List Macros...","list-macros","ncw","help Bind Key dialog","Lists saved recorded macros";
      "-","","","","";
      "Set Macro &Variable...","gui-set-var\tset-var","ncw","help set variable dialog box","Sets global macro variable";
      "Start Slick-C® Debugger...","slickc-debug-start","ncw","help Debug","Activates the Slick-C® debugger window";
      submenu "Slick-C® Profiler","help macro menu","Displays menu of Slick-C profiling options","ncw" {
         "&Begin Profiling","profile","ncw","help macro menu","Starts the Slick-C profiler";
         "&Finish Profiling...","profile view","ncw","help macro menu","Stop the Slick-C profiler and view results in profiler dialog";
         "Profile &Keystroke...","profile key","ncw","help macro menu","Profile a single keystroke and view results in profiler dialog";
         "&Save...","profile save","ncw","help macro menu","Save last profiling results to a text file";
         "&Load...","profile load","ncw","help macro menu","Load profiling results from a text file and view them in profiler dialog";
      }
      "-","","","","";
      "&Go to Slick-C® Definition...","gui-find-proc\tfind-proc","ncw","help Macro Menu","Opens a macro source file and places your cursor on the definition of a macro symbol";
      "Find Slick-C® &Error","find-error","ncw","help Macro Menu","Places your cursor on the macro source line which caused the last interpreter run-time error";
      "-","","","","";
      "&New Form...","new-form","ncw","help macro menu","Opens a new form for editing with dialog editor";
      "&Open Form...","open-form\topen-form","ncw","help macro menu","Opens an existing or new form for editing with dialog editor";
      "Sele&cted Form...","show-selected","ncw","help window menu","Displays edited form window currently selected";
      "Load and Run &Form\tShift+Space","run-selected","ncw","help macro menu","Loads form, loads Slick-C® code, and runs the currently selected/edited form.";
      "Grid...","gui-grid\tgrid","ncw","help macro menu","Sets form grid settings";
      "&Menus...","open-menu","ncw","help Open Menu dialog box","Opens an existing or new menu for editing";
      "&Insert Form or Menu Source...","insert-object","nrdonly","help macro menu","Insert source code into current file for a form you specify";
   }
   submenu "&Tools","help Tools menu","Displays Tools menu containing miscellaneous editor commands","ncw" {
      "&Options...","config","","","";
      "&Quick Start Configuration...","quick-start","","","";
      "-","","","","";
      "Regex Evaluator...","activate-regex-evaluator","","help Regex Evaluator","Shows the Regex Evaluator tool window";
      "OS She&ll","launch-os-shell","","help Tools menu","Runs operating system command shell";
      "OS &File Browser...","explore","","help Tools menu","Runs operating system file system browser";
      "Calculator","calculator","ncw","help calculator dialog box","Evaluates mathematical expressions you specify";
      "&Add Selected Expr","add","sel|nicon|nrdonly","help Tools menu","Adds the result of evaluating each line in a selected area of text";
      "ASCII &Table","ascii-table","ncw","help Tools menu","Opens ASCII table file";
      "Generate GUID...","gui-insert-guid","","help Tools menu","Shows the GUID generator dialog";
      "-","","","","";
      submenu "&Version Control","help Version Control Menu","Displays version control menu","version-control" {
         "Check &In","vccheckin","update","help Version Control Menu","Checks in current file";
         "&Get","vcget","get","help Version Control Menu","Checks out current file read only";
         "Check &Out","vccheckout","checkout","help Version Control Menu","Checks out current file";
         "Lock","vclock","lock","help Version Control Menu","Locks the current file without checking out the file";
         "U&nlock","vcunlock","uncheckout","help Version Control Menu","Unlocks the current file without checking in the file";
         "-","","","","";
         "&Add","vcadd","add","help Version Control Menu","Adds current file to version control";
         "&Remove","vcremove","remove","help Version Control Menu","Removes current file from version control";
         "-","","","","";
         "&History...","vchistory","history","help Version Control Menu","Views history for current file";
         "&Difference...","vcdiff","diff","help Version Control Menu","Views differences of current file";
         "&Properties...","vcproperties","properties","help Version Control Menu","Views properties of current file";
         "&Manager...","vcmanager","manager","help Version Control Menu","Executes Version Control Manager";
         "-","","","","";
         "&Setup...","vcsetup","","help Version Control Setup dialog box","Allows you to choose and configure a Version Control System interface";
      }
      "-","","","","";
      submenu "C++ &Refactoring","","Displays C++ refactoring menu","cpp_refactoring" {
         "-","","bar","","";
         "Test Parsing Configuration...","refactor_parse","parse","","View and test C++ Refactoring settings for the current file";
         "C/C++ C&ompiler Options...","refactor_options","options","","Allows you to configure C++ Refactoring options";
      }
      submenu "&Quick Refactoring","help Quick Refactoring","Displays Quick refactoring menu","quick_refactoring" {
         "&Rename...","refactor_quick_rename","quick_rename","help Quick Refactoring Menu","Rename symbol";
         "Extract Method...","refactor_quick_extract_method","quick_extract_method","Help Quick Refactoring Menu","Extract the selected code block into a new function";
         "Modify Parameter List...","refactor_quick_modify_params","quick_modify_params","help Quick Refactoring Menu","Modify the parameter list of a method";
         "Replace Literal with Constant...","refactor_quick_replace_literal","quick_replace_literal","help Quick Refactoring Menu","Replace literal value with a declared constant";
      }
      submenu "Im&ports","help Imports","Displays Imports refactoring menu","imports" {
         "Organize Imports","jrefactor_organize_imports","organize_imports","help Refactoring Menu","Organize import statements in a java file";
         "Add Import","jrefactor_add_import","add_import","help Refactoring Menu","Add import statement for symbol under cursor";
         "-","","bar","","";
         "Options...","jrefactor_organize_imports_options","organize_imports_options","help Organize Imports Options","View options for Organize Imports operations";
      }
      "Generate debug","generate_debug","nicon|nrdonly","help generate debug","Generates debug code for symbol under the cursor";
      "-","","","","";
      "Sort...","gui-sort","nicon|nrdonly","help sort dialog box","Sorts current buffer or selected text";
      "&Beautify...","gui_beautify","","help Tools Menu","Displays language specific beautifier dialog box used for setting options and beautifying source";
      "File &Merge...","merge","ncw","help 3 Way Merge Setup dialog box","Merges two sets of changes made to a file";
      "File &Difference...","diff","ncw","help Diff Setup dialog box","Shows and edits differences between files";
      submenu "&Spell Check","help spell check menu","Displays menu of spell checking commands","ncw" {
         "&Check from Cursor","spell-check","nrdonly|nicon","help spell check menu","Spell check starting from cursor";
         "C&heck Comments and Strings","spell-check-source","nicon|nrdonly","help spell check menu","Spell check comments and strings";
         "Check &Selection","spell-check-selection","nrdonly|ab-sel|nicon","help spell check menu","Spell check words in selection";
         "Check &Word at Cursor","spell-check-word","nrdonly|nicon","help spell check menu","Spell check word at cursor";
         "Check &Files...","spell-check-files","ncw","help spell check menu","Spell check multiple source files (HTML,...)";
         "-","","","","";
         "Spell &Options...","spell-options","ncw","help spell options dialog box","Display/modify spell checker options";
      }
      "-","","","","";
      "Tag F&iles...","gui-make-tags\tmake-tags","ncw","help Context Tagging - Tag Files dialog","Builds tag files for use by the symbol browser and other tagging features";
   }
   submenu "&Window","help window menu","Displays menu of window commands","ncw" {
      "&Cascade","cascade-windows","","help window menu","Cascades edit windows";
      "&Tile","tile-windows","","help window menu","Tiles edit windows";
      "Tile Ho&rizontal","tile-windows h","","help window menu","Tiles edit windows horizontally when there are 3 or less windows";
      "&Arrange Icons","arrange-icons","icon","help window menu","Rearranges iconized windows";
      "-","","","","";
      "&Next","next-window","mto-window","help window menu","Switches to next window";
      "&Previous","prev-window","mto-window","help window menu","Switches to previous window";
      "Close","close-window","","help window menu","Closes the current window";
      "&Font...","wfont","","help window font dialog box","Sets/views font for current window or all windows";
      "-","","","","";
      "Split &Horizontally","hsplit-window","nicon","help window menu","Splits the current window horizontally in half";
      "Split &Vertically","vsplit-window","nicon","help window menu","Splits the current window vertically in half";
      "&Zoom Toggle","zoom-window","","help window menu","Zooms or unzooms the current window";
      "&One Window","one-window","","help window menu","Zooms the current window and deletes all other windows";
      "&Duplicate","duplicate-window","","help window menu","Creates another window linked to the current buffer";
      "&Link Window...","link-window","","help link window dialog box","Selects buffer to display in current window";
      "-","","","","";
   }
   submenu "&Help","help help menu","Displays menu of help commands","ncw" {
      "&Contents","help -contents","ncw","help help menu","Displays help on table of contents";
      "Index...","help -index","ncw","help help menu","Displays help index and allows you to search the index";
      "&Search...","help -search","ncw","help help menu","Displays help index and allows you to enter a help item";
      "New Features","help new features","ncw","help help menu","Displays SlickEdit new features";
      "Cool Features","cool_features","ncw","help help menu","Displays SlickEdit feature tips";
      "Quick Start","help Quick Start","ncw","help help menu","Displays SlickEdit Quick Start documentation";
      "-","","","","";
      "&Keys Help","help summary of keys","ncw","help help menu","Displays summary of key bindings for the current emulation";
      "&What Is Key...","what-is","ncw","help help menu","Displays help on command invoked by a key you specify";
      "&Where Is Command...","where-is","ncw","help help menu","Displays which key(s) the specified command is bound to";
      "&Macro Functions by Category","help macro_functions_by_category","ncw","help help menu","Allows you to choose help on macro functions by category";
      "Frequently Asked &Questions","goto_faq","ncw","help help menu","Answers to common user questions";
      "-","","","","";
      "F1 &Index Help...","help_index","ncw","help Help Menu","Search F1 index file for help on a word";
      "Configure F1 Index &File...","configure_index_file","ncw","help Help Menu","View/modify index file used by F1 word help";
      "Configure F1 MSD&N Help...","msdn_configure_collection","ncw","help Configure F1 MSDN help","Enable and configure MSDN Library F1 word help";
      "-","","","","";
      submenu "Licensing","help help menu","Displays license menu","ncw" {
         "License Manager...","lmw 1","","help help menu","Manage license";
         "Borrow License...","lm-borrow","","help help menu","Manage license";
         "Return License...","lm-return","","help help menu","Manage license";
      }
      submenu "Product &Updates","","Displays Update Manager menus","ncw" {
         "New Updates...","upcheck_display","","","Check for new updates";
         "Options...","upcheck_options","","","Set Update Manager options";
         "-","","","","";
         "Load Hot Fix...","load_hotfix","","","Load a hot fix for the current release";
         "List Installed Fixes...","list_hotfixes","","","List hot fixes already installed";
         "Apply Available Hot Fix...","hotfix_auto_apply","","","Apply available hot fixes";
      }
      "&Register Product...","online_registration","","help help menu","Displays SlickEdit Inc. on-line registration dialog";
      "SlickEdit Support Web Site","goto-slickedit","","help help menu","Displays SlickEdit Inc. home page in your Web browser";
      "Contact Product Support","do-webmail-support","","help help menu","Use web-based form to contact product support";
      "Check Maintenance","check-maintenance","","help help menu","Check the status of your maintenance and support agreement";
      "-","","","","";
      "&About SlickEdit","version","ncw","help help menu","Displays version and serial number information";
   }
}
_form _tbfilelist_form {
   p_backcolor=0x80000005;
   p_border_style=BDS_SIZABLE;
   p_caption='Files';
   p_CaptionClick=true;
   p_clip_controls=true;
   p_forecolor=0x80000008;
   p_height=5390;
   p_help='Files tool window';
   p_picture='ptfiles.bmp';
   p_tool_window=true;
   p_width=3552;
   p_x=3852;
   p_y=2376;
   p_eventtab=_tbfilelist_form;
   p_eventtab2=_toolbar_etab2;
   _sstab ctl_sstab {
      p_FirstActiveTab=0;
      p_backcolor=0x80000005;
      p_clip_controls=false;
      p_DropDownList=false;
      p_forecolor=0x80000008;
      p_Grabbar=false;
      p_GrabbarLocation=SSTAB_GRABBARLOCATION_TOP;
      p_height=3780;
      p_MultiRow=SSTAB_MULTIROW_NONE;
      p_NofTabs=3;
      p_Orientation=SSTAB_OTOP;
      p_PaddingX=4;
      p_PaddingY=4;
      p_PictureOnly=false;
      p_tab_index=0;
      p_tab_stop=false;
      p_TabsPerRow=5;
      p_width=4080;
      p_x=0;
      p_y=0;
      p_eventtab2=_ul2_sstabb;
      _sstab_container  {
         p_ActiveCaption='Buffers';
         p_ActiveEnabled=true;
         p_ActiveOrder=0;
         p_ActiveColor=0x80000008;
         p_ActiveToolTip='List all open files';
         _text_box ctl_filter {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_completion=NONE_ARG;
            p_forecolor=0x80000008;
            p_height=242;
            p_tab_index=1;
            p_tab_stop=true;
            p_width=2400;
            p_x=570;
            p_y=45;
            p_eventtab2=_ul2_textbox;
         }
         _tree_view ctl_file_list {
            p_after_pic_indent_x=50;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_clip_controls=false;
            p_CheckListBox=false;
            p_CollapsePicture='_treesave.bmp';
            p_ColorEntireLine=false;
            p_EditInPlace=false;
            p_delay=0;
            p_ExpandPicture='_treesave_blank.bmp';
            p_forecolor=0x80000008;
            p_Gridlines=TREE_GRID_VERT;
            p_height=3060;
            p_LeafPicture='';
            p_LevelIndent=0;
            p_LineStyle=TREE_NO_LINES;
            p_multi_select=MS_SIMPLE_LIST;
            p_NeverColorCurrent=false;
            p_ShowRoot=false;
            p_AlwaysColorCurrent=false;
            p_SpaceY=50;
            p_scroll_bars=SB_VERTICAL;
            p_UseFileInfoOverlays=FILE_OVERLAYS_NODE;
            p_tab_index=2;
            p_tab_stop=true;
            p_width=4005;
            p_x=15;
            p_y=360;
            p_eventtab2=_ul2_tree;
         }
         _label ctlfilter_label {
            p_alignment=AL_LEFT;
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_caption='Filter:';
            p_forecolor=0x80000008;
            p_height=176;
            p_tab_index=3;
            p_width=396;
            p_word_wrap=false;
            p_x=90;
            p_y=60;
         }
         _image ctl_save_button {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_forecolor=0x80000008;
            p_height=297;
            p_max_click=MC_SINGLE;
            p_message='Save Selected File(s) (Ctrl + S)';
            p_Nofstates=1;
            p_picture='bbsave.ico';
            p_stretch=false;
            p_style=PSPIC_HIGHLIGHTED_BUTTON;
            p_tab_index=4;
            p_value=0;
            p_width=324;
            p_x=3120;
            p_y=30;
            p_eventtab2=_ul2_picture;
         }
         _image ctl_close_button {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_forecolor=0x80000008;
            p_height=297;
            p_max_click=MC_SINGLE;
            p_message='Close Selected Files(s) (Alt + C)';
            p_Nofstates=1;
            p_picture='bbclose.ico';
            p_stretch=false;
            p_style=PSPIC_HIGHLIGHTED_BUTTON;
            p_tab_index=5;
            p_value=0;
            p_width=324;
            p_x=3420;
            p_y=30;
            p_eventtab2=_ul2_picture;
         }
         _image ctl_diff_button {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_forecolor=0x80000008;
            p_height=297;
            p_max_click=MC_SINGLE;
            p_message='Diff Selected Files(s) (Ctrl + =)';
            p_Nofstates=1;
            p_picture='bbdiff.ico';
            p_stretch=false;
            p_style=PSPIC_HIGHLIGHTED_BUTTON;
            p_tab_index=6;
            p_value=0;
            p_width=324;
            p_x=3720;
            p_y=30;
            p_eventtab2=_ul2_picture;
         }
      }
      _sstab_container  {
         p_ActiveCaption='Project';
         p_ActiveEnabled=true;
         p_ActiveOrder=1;
         p_ActiveColor=0x80000008;
         p_ActiveToolTip='Find and open files from current project';
         _text_box ctl_proj_filter {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_completion=NONE_ARG;
            p_forecolor=0x80000008;
            p_height=242;
            p_tab_index=1;
            p_tab_stop=true;
            p_width=3375;
            p_x=570;
            p_y=45;
            p_eventtab=_tbfilelist_form.ctl_filter;
            p_eventtab2=_ul2_textbox;
         }
         _label ctllabel1 {
            p_alignment=AL_LEFT;
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_caption='Filter:';
            p_forecolor=0x80000008;
            p_height=176;
            p_tab_index=2;
            p_width=396;
            p_word_wrap=false;
            p_x=90;
            p_y=60;
         }
         _tree_view ctl_project_list {
            p_after_pic_indent_x=50;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_clip_controls=false;
            p_CheckListBox=false;
            p_CollapsePicture='_treesave.bmp';
            p_ColorEntireLine=false;
            p_EditInPlace=false;
            p_delay=0;
            p_ExpandPicture='_treesave_blank.bmp';
            p_forecolor=0x80000008;
            p_Gridlines=TREE_GRID_VERT;
            p_height=3060;
            p_LeafPicture='';
            p_LevelIndent=0;
            p_LineStyle=TREE_NO_LINES;
            p_multi_select=MS_SIMPLE_LIST;
            p_NeverColorCurrent=false;
            p_ShowRoot=false;
            p_AlwaysColorCurrent=false;
            p_SpaceY=50;
            p_scroll_bars=SB_VERTICAL;
            p_UseFileInfoOverlays=FILE_OVERLAYS_NODE;
            p_tab_index=3;
            p_tab_stop=false;
            p_width=4080;
            p_x=0;
            p_y=360;
            p_eventtab=_tbfilelist_form.ctl_file_list;
            p_eventtab2=_ul2_tree;
         }
      }
      _sstab_container  {
         p_ActiveCaption='Workspace';
         p_ActiveEnabled=true;
         p_ActiveOrder=2;
         p_ActiveColor=0x80000008;
         p_ActiveToolTip='Find and open files from current workspace';
         _text_box ctl_wksp_filter {
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_completion=NONE_ARG;
            p_forecolor=0x80000008;
            p_height=242;
            p_tab_index=1;
            p_tab_stop=true;
            p_width=3390;
            p_x=570;
            p_y=45;
            p_eventtab=_tbfilelist_form.ctl_filter;
            p_eventtab2=_ul2_textbox;
         }
         _tree_view ctl_workspace_list {
            p_after_pic_indent_x=50;
            p_backcolor=0x80000005;
            p_border_style=BDS_FIXED_SINGLE;
            p_clip_controls=false;
            p_CheckListBox=false;
            p_CollapsePicture='_treesave.bmp';
            p_ColorEntireLine=false;
            p_EditInPlace=false;
            p_delay=0;
            p_ExpandPicture='_treesave_blank.bmp';
            p_forecolor=0x80000008;
            p_Gridlines=TREE_GRID_VERT;
            p_height=3060;
            p_LeafPicture='';
            p_LevelIndent=0;
            p_LineStyle=TREE_NO_LINES;
            p_multi_select=MS_SIMPLE_LIST;
            p_NeverColorCurrent=false;
            p_ShowRoot=false;
            p_AlwaysColorCurrent=false;
            p_SpaceY=50;
            p_scroll_bars=SB_VERTICAL;
            p_UseFileInfoOverlays=FILE_OVERLAYS_NODE;
            p_tab_index=2;
            p_tab_stop=true;
            p_width=4020;
            p_x=0;
            p_y=360;
            p_eventtab=_tbfilelist_form.ctl_file_list;
            p_eventtab2=_ul2_tree;
         }
         _label ctllabel2 {
            p_alignment=AL_LEFT;
            p_auto_size=true;
            p_backcolor=0x80000005;
            p_border_style=BDS_NONE;
            p_caption='Filter:';
            p_forecolor=0x80000008;
            p_height=176;
            p_tab_index=3;
            p_width=396;
            p_word_wrap=false;
            p_x=90;
            p_y=60;
         }
      }
   }
}

defmain()
{
}
