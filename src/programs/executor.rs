use common::elf::*;
use common::string::*;

use drivers::keyboard::*;
use drivers::mouse::*;

use filesystems::unfs::*;

use programs::session::*;

pub struct Executor {
    executable: ELF,
    entry: usize,
    draw: usize,
    on_key: usize,
    on_mouse: usize
}

impl Executor {
    unsafe fn entry(&self){
        if self.executable.can_call(self.entry){
            //Rediculous call mechanism
            self.executable.map();
            let fn_ptr: *const usize = &self.entry;
            (*(fn_ptr as *const fn()))();
            self.executable.unmap();
        }
    }
}

impl SessionItem for Executor {
    fn new(file: String) -> Executor {
        let mut ret = Executor {
            executable: ELF::new(),
            entry: 0,
            draw: 0,
            on_mouse: 0,
            on_key: 0
        };

        if file.len() > 0{
            unsafe{
                ret.executable = ELF::from_data(UnFS::new().load(file));
                //ret.executable.d();

                ret.entry = ret.executable.entry();
                ret.draw = ret.executable.symbol("draw".to_string());
                ret.on_key = ret.executable.symbol("on_key".to_string());
                ret.on_mouse = ret.executable.symbol("on_mouse".to_string());

                ret.entry();
            }
        }

        return ret;
    }

    fn draw(&mut self, session: &mut Session) -> bool{
        unsafe {
            if self.executable.can_call(self.draw){
                //Rediculous call mechanism
                self.executable.map();
                let fn_ptr: *const usize = &self.draw;
                let ret = (*(fn_ptr as *const fn(&mut Session) -> bool))(session);
                self.executable.unmap();

                return ret;
            }
        }
        return false;
    }

    fn on_key(&mut self, session: &mut Session, key_event: KeyEvent){
        unsafe {
            if self.executable.can_call(self.on_key){
                //Rediculous call mechanism
                self.executable.map();
                let fn_ptr: *const usize = &self.on_key;
                (*(fn_ptr as *const fn(&mut Session, KeyEvent)))(session, key_event);
                self.executable.unmap();
            }
        }
    }

    fn on_mouse(&mut self, session: &mut Session, mouse_event: MouseEvent, allow_catch: bool) -> bool{
        unsafe {
            if self.executable.can_call(self.on_mouse){
                //Rediculous call mechanism
                self.executable.map();
                let fn_ptr: *const usize = &self.on_mouse;
                let ret = (*(fn_ptr as *const fn(&mut Session, MouseEvent, bool) -> bool))(session, mouse_event, allow_catch);
                self.executable.unmap();
                return ret;
            }
        }
        return false;
    }
}