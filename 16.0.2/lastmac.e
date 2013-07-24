#include "slick.sh"
_command last_recorded_macro() name_info(','VSARG2_MARK|VSARG2_REQUIRES_EDITORCTL)
{
   _macro('R',1);
   deselect();
   _select_char('','E');
   next_word();
   next_word();
   cursor_left(3);
   select_it('CHAR','','E');
   copy_to_clipboard();
   end_line();
   c_enter();
   paste();
   linewrap_rubout();
   linewrap_rubout();
   linewrap_rubout();
   linewrap_rubout();
   last_event(name2event(' '));c_space();
   keyin('=');
   last_event(name2event(' '));c_space();
   last_event(name2event('('));c_paren();
   keyin("1");
   last_event(name2event(' '));c_space();
   AutoBracketKeyin('<');
   AutoBracketKeyin('<');
   last_event(name2event(' '));c_space();
   paste();
   end_line();
   keyin(",");
   begin_line_text_toggle();
   cursor_down();
}
