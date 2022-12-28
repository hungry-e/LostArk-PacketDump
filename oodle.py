import ctypes
import shutil
import struct
import winreg
from pathlib import Path
import typing


class Oodle:
    def __init__(self, oodle_dll: Path, oodle_state: Path) -> None:
        """ Initialize Oodle DLL for decompressing. 
        
        Looking at QuickBMS source code could help to understand
        figure this out https://aluigi.altervista.org/quickbms.htm
        """

        # Ensure that Oodle DLL is available
        if not oodle_dll.exists():
            source_dll = self.get_oodle_dll_from_winreg()
            if source_dll is None:
                raise RuntimeError(f'Missing {oodle_dll}')
            shutil.copy(source_dll, oodle_dll)

        self._win_dll = ctypes.WinDLL(str(oodle_dll))

        # Read dumped state values
        with open(oodle_state, 'rb') as f:
            f.seek(0x08)
            shared_bits, compact_shared_size = struct.unpack('ii', f.read(0x08))
            f.seek(0x18)
            compact_state_size, _ = struct.unpack('ii', f.read(0x08))
            # Don't allow garbage collector to delete this
            self._compact_shared = ctypes.create_string_buffer(f.read(compact_shared_size), compact_shared_size)
            self._compact_shared_ref = ctypes.cast(self._compact_shared, ctypes.POINTER(ctypes.c_ubyte))

            compact_state = ctypes.create_string_buffer(f.read(compact_state_size), compact_state_size)

        # Create a state buffer
        oodle_state_size = self._win_dll['OodleNetwork1UDP_State_Size']
        oodle_state_size.argtypes = []
        # Don't allow garbage collector to delete this
        self._state = ctypes.create_string_buffer(oodle_state_size())
        self._state_ref = ctypes.cast(self._state, ctypes.POINTER(ctypes.c_ubyte))

        # Fill the state buffer
        oodle_state_uncompact = self._win_dll['OodleNetwork1UDP_State_Uncompact']
        oodle_state_uncompact.restype = ctypes.c_bool
        oodle_state_uncompact.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte)
        ]
        if (not oodle_state_uncompact(self._state_ref, ctypes.cast(compact_state, ctypes.POINTER(ctypes.c_ubyte)))):
            raise Exception('oodle init fail')

        # Create a shared buffer
        # TODO: underhood = 0x18 + ((1 << shared_bits) * 8)
        oodle_shared_size = self._win_dll['OodleNetwork1_Shared_Size']
        oodle_shared_size.argtypes = [ctypes.c_int] # shared_bits
        # Don't allow garbage collector to delete this
        self._shared = ctypes.create_string_buffer(oodle_shared_size(shared_bits))
        self._shared_ref = ctypes.cast(self._shared, ctypes.POINTER(ctypes.c_ubyte))

        # Fill the shared buffer
        oodle_shared_setwindow = self._win_dll['OodleNetwork1_Shared_SetWindow']
        oodle_shared_setwindow.restype = None
        oodle_shared_setwindow.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int
        ]
        oodle_shared_setwindow(
            ctypes.cast(self._shared_ref, ctypes.POINTER(ctypes.c_ubyte)),
            shared_bits, 
            self._compact_shared_ref,
            compact_shared_size
        )

    def decompress(self, data: bytes) -> bytes:
        """ Decompress data by calling Oodle DLL. """

        out_size, = struct.unpack_from('i', data)

        payload = ctypes.create_string_buffer(data[4:])
        out = ctypes.create_string_buffer(out_size)

        oodle_decode = self._win_dll['OodleNetwork1UDP_Decode']
        oodle_decode.restype = ctypes.c_bool
        oodle_decode.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_ubyte),
            ctypes.c_int
        ]
    
        if (not oodle_decode(self._state_ref, self._shared_ref,
            ctypes.cast(payload, ctypes.POINTER(ctypes.c_ubyte)), len(data) - 4,
            ctypes.cast(out, ctypes.POINTER(ctypes.c_ubyte)), out_size)):
            raise Exception('oodle decompress fail')
        return bytes(out.raw)

    @staticmethod
    def get_oodle_dll_from_winreg() -> Path | None:
        """ Find Lost Ark installation path in Windows Registry. """

        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1599340')
        except WindowsError:
            return None
        try:
            value, _ = winreg.QueryValueEx(key, 'InstallLocation')
        except WindowsError:
            return None
        finally:
            winreg.CloseKey(key)
        return Path(value, 'Binaries', 'Win64', 'oo2net_9_win64.dll')


oodle = Oodle(Path('assets', 'oo2net_9_win64.dll'), Path('assets', 'oodle_state.bin'))
