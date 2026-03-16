/* RECT utility thunks: SetRect, CopyRect, geometry operations */
#include "../win32_thunks.h"
#include "../../log.h"

void Win32Thunks::RegisterWindowRectHandlers() {
    Thunk("SetRect", 103, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        mem.Write32(regs[0], regs[1]); mem.Write32(regs[0]+4, regs[2]);
        mem.Write32(regs[0]+8, regs[3]); mem.Write32(regs[0]+12, ReadStackArg(regs,mem,0));
        regs[0] = 1; return true;
    });
    Thunk("CopyRect", 96, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, mem.Read32(regs[1]+i*4));
        regs[0] = 1; return true;
    });
    Thunk("SetRectEmpty", 104, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        for (int i=0;i<4;i++) mem.Write32(regs[0]+i*4, 0); regs[0] = 1; return true;
    });
    Thunk("InflateRect", 98, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        int32_t dx=(int32_t)regs[1],dy=(int32_t)regs[2];
        mem.Write32(regs[0],l-dx); mem.Write32(regs[0]+4,t-dy); mem.Write32(regs[0]+8,r+dx); mem.Write32(regs[0]+12,b+dy);
        regs[0]=1; return true;
    });
    Thunk("OffsetRect", 101, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        OffsetRect(&rc,(int)regs[1],(int)regs[2]);
        mem.Write32(regs[0],rc.left); mem.Write32(regs[0]+4,rc.top);
        mem.Write32(regs[0]+8,rc.right); mem.Write32(regs[0]+12,rc.bottom);
        regs[0]=1; return true;
    });
    Thunk("IntersectRect", 99, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = IntersectRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top);
        mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("UnionRect", 106, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT a,b,out;
        a.left=mem.Read32(regs[1]); a.top=mem.Read32(regs[1]+4); a.right=mem.Read32(regs[1]+8); a.bottom=mem.Read32(regs[1]+12);
        b.left=mem.Read32(regs[2]); b.top=mem.Read32(regs[2]+4); b.right=mem.Read32(regs[2]+8); b.bottom=mem.Read32(regs[2]+12);
        BOOL ret = UnionRect(&out,&a,&b);
        mem.Write32(regs[0],out.left); mem.Write32(regs[0]+4,out.top); mem.Write32(regs[0]+8,out.right); mem.Write32(regs[0]+12,out.bottom);
        regs[0]=ret; return true;
    });
    Thunk("PtInRect", 102, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        RECT rc; rc.left=mem.Read32(regs[0]); rc.top=mem.Read32(regs[0]+4);
        rc.right=mem.Read32(regs[0]+8); rc.bottom=mem.Read32(regs[0]+12);
        POINT pt={(LONG)regs[1],(LONG)regs[2]}; regs[0]=PtInRect(&rc,pt); return true;
    });
    Thunk("IsRectEmpty", 100, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        int32_t l=mem.Read32(regs[0]),t=mem.Read32(regs[0]+4),r=mem.Read32(regs[0]+8),b=mem.Read32(regs[0]+12);
        regs[0]=(r<=l||b<=t)?1:0; return true;
    });
    Thunk("EqualRect", 97, [this](uint32_t* regs, EmulatedMemory& mem) -> bool {
        bool eq=true; for(int i=0;i<4;i++) if(mem.Read32(regs[0]+i*4)!=mem.Read32(regs[1]+i*4)) eq=false;
        regs[0]=eq?1:0; return true;
    });
    Thunk("SubtractRect", 105, [](uint32_t* regs, EmulatedMemory&) -> bool { regs[0]=0; return true; });
}
