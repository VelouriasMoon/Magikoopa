#include "hooks.h"
#include "hooklinker.h"

quint32 Hook::makeBranchOpcode(quint32 src, quint32 dest, bool link, quint32 condition)
{
    quint32 ret;
    switch (condition)
    {
        case 0:
            ret = 0x0A000000;
            break;
        case 1:
            ret = 0x1A000000;
            break;
        case 2:
            ret = 0x2A000000;
            break;
        case 3:
            ret = 0x3A000000;
            break;
        case 4:
            ret = 0x4A000000;
            break;
        case 5:
            ret = 0x5A000000;
            break;
        case 6:
            ret = 0x6A000000;
            break;
        case 7:
            ret = 0x7A000000;
            break;
        case 8:
            ret = 0x8A000000;
            break;
        case 9:
            ret = 0x9A000000;
            break;
        case 10:
            ret = 0xAA000000;
            break;
        case 11:
            ret = 0xBA000000;
            break;
        case 12:
            ret = 0xCA000000;
            break;
        case 13:
            ret = 0xDA000000;
            break;
        case 14:
            ret = 0xEA000000;
            break;
        default:
            ret = 0xEA000000;
    }

    if (link) ret |= 0x01000000;

    int offset = (dest / 4) - (src / 4) - 2;
    offset &= 0x00FFFFFF;

    ret |= offset;

    return ret;
}

quint32 Hook::offsetOpcode(quint32 opcode, quint32 orgPosition, qint32 newPosition)
{
    quint32 fixedOpcode = opcode;

    quint8 nybble14 = (opcode >> 24) & 0xF;

    // TODO: Add more fixeable opcodes
    //  BX (12/01)
    //  BLX (12/03)

    // Fix Branches (B/BL)
    if (nybble14 >= 0xA && nybble14 <= 0xB)
    {
        fixedOpcode &= 0xFF000000;

        qint32 oldOffset = opcode & 0x00FFFFFF;
        oldOffset = (oldOffset + 2) * 4;

        quint32 dest = orgPosition + oldOffset;

        qint32 newOffset = (dest / 4) - (newPosition / 4) - 2;

        fixedOpcode |= newOffset & 0x00FFFFFF;
    }

    return fixedOpcode;
}

Hook::~Hook()
{
    delete m_info;
}

void Hook::base(HookLinker* parent, HookInfo* info)
{
    m_parent = parent;
    m_info = info;

    // TODO: Make this multi-region by adding region suffixes
    //       If suffix does not exist fall back to "addr"

    QString addrKey = "addr";

    if (info->has("symb"))
    {
        if (!info->has("symb"))
            throw new HookExeption(info, "No Symbol given");

        bool ok;
        m_address = parent->symTable()->get(info->get("symb"), &ok);

        if (!ok)
            throw new HookExeption(info, QString("Function name \"%1\" not found").arg(info->get("func")));

        if (info->has(addrKey))
        {
            m_address = m_address + info->getUint("addr");
        }
    }
    else
    {
        if (!info->has(addrKey))
            throw new HookExeption(info, "No address given");

        m_address = info->getUint("addr");
    }

    if (m_address < 0x100000)
        throw new HookExeption(info, QString("Invalid address \"%1\"").arg(info->get("addr")));
}


BranchHook::BranchHook(HookLinker* parent, HookInfo* info)
{
    base(parent, info);

    if (!info->has("link"))
        throw new HookExeption(info, "Invalid branch link type");

    m_link = info->getBool("link");

    if (info->has("func"))
    {
        if (!parent->symTable())
            throw new HookExeption(info, "Invalid SymTable");

        bool ok;
        m_destination = parent->symTable()->get(info->get("func"), &ok);

        if (!ok)
            throw new HookExeption(info, QString("Function name \"%1\" not found").arg(info->get("func")));
    }
    else
    {
        if (!info->has("dest"))
            throw new HookExeption(info, "No branch destination given");

        bool ok;
        m_destination = info->getUint("dest", &ok);

        if (!ok)
            throw new HookExeption(info, QString("Invalid branch destination \"%1\"").arg(info->get("dest")));
    }

    if (info->has("cond"))
    {
        QString opcodePosStr = info->get("cond").toLower();
        if (opcodePosStr == "eq")
            m_opcodecon = Opcode_EQ;
        else if (opcodePosStr == "ne")
            m_opcodecon = Opcode_NE;
        else if (opcodePosStr == "cs")
            m_opcodecon = Opcode_CS;
        else if (opcodePosStr == "cc")
            m_opcodecon = Opcode_CC;
        else if (opcodePosStr == "mi")
            m_opcodecon = Opcode_MI;
        else if (opcodePosStr == "pl")
            m_opcodecon = Opcode_PL;
        else if (opcodePosStr == "vs")
            m_opcodecon = Opcode_VS;
        else if (opcodePosStr == "vc")
            m_opcodecon = Opcode_VC;
        else if (opcodePosStr == "hi")
            m_opcodecon = Opcode_HI;
        else if (opcodePosStr == "ls")
            m_opcodecon = Opcode_LS;
        else if (opcodePosStr == "ge")
            m_opcodecon = Opcode_GE;
        else if (opcodePosStr == "lt")
            m_opcodecon = Opcode_LT;
        else if (opcodePosStr == "gt")
            m_opcodecon = Opcode_GT;
        else if (opcodePosStr == "le")
            m_opcodecon = Opcode_LE;
        else if (opcodePosStr == "none")
            m_opcodecon = Opcode_None;
        else
            throw new HookExeption(info, QString("Invalid branch condition \"%1\"").arg(info->get("cond")));
    }
    else
        m_opcodecon = Opcode_None;
}

void BranchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);
    file->write32(makeBranchOpcode(m_address, m_destination, m_link, m_opcodecon));
}


SoftBranchHook::SoftBranchHook(HookLinker* parent, HookInfo* info)
{
    base(parent, info);

    if (info->has("func"))
    {
        if (!parent->symTable())
            throw new HookExeption(info, "Invalid SymTable");

        bool ok;
        m_destination = parent->symTable()->get(info->get("func"), &ok);

        if (!ok)
            throw new HookExeption(info, QString("Function name \"%1\" not found").arg(info->get("func")));
    }
    else
    {
        if (!info->has("dest"))
            throw new HookExeption(info, "No branch destination given");

        bool ok;
        m_destination = info->getUint("dest", &ok);

        if (!ok)
            throw new HookExeption(info, QString("Invalid branch destination \"%1\"").arg(info->get("dest")));
    }

    if (info->has("opcode"))
    {
        QString opcodePosStr = info->get("opcode").toLower();
        if (opcodePosStr == "pre")
            m_opcodePos = Opcode_Pre;
        else if (opcodePosStr == "post")
            m_opcodePos = Opcode_Post;
        else if (opcodePosStr == "ignore")
            m_opcodePos = Opcode_Ignore;
        else
            throw new HookExeption(info, QString("Invalid softHook opcode position \"%1\"").arg(info->get("opcode")));
    }
    else
        m_opcodePos = Opcode_Ignore;

    if (info->has("cond"))
    {
        QString opcodePosStr = info->get("cond").toLower();
        if (opcodePosStr == "eq")
            m_opcodecon = Opcode_EQ;
        else if (opcodePosStr == "ne")
            m_opcodecon = Opcode_NE;
        else if (opcodePosStr == "cs")
            m_opcodecon = Opcode_CS;
        else if (opcodePosStr == "cc")
            m_opcodecon = Opcode_CC;
        else if (opcodePosStr == "mi")
            m_opcodecon = Opcode_MI;
        else if (opcodePosStr == "pl")
            m_opcodecon = Opcode_PL;
        else if (opcodePosStr == "vs")
            m_opcodecon = Opcode_VS;
        else if (opcodePosStr == "vc")
            m_opcodecon = Opcode_VC;
        else if (opcodePosStr == "hi")
            m_opcodecon = Opcode_HI;
        else if (opcodePosStr == "ls")
            m_opcodecon = Opcode_LS;
        else if (opcodePosStr == "ge")
            m_opcodecon = Opcode_GE;
        else if (opcodePosStr == "lt")
            m_opcodecon = Opcode_LT;
        else if (opcodePosStr == "gt")
            m_opcodecon = Opcode_GT;
        else if (opcodePosStr == "le")
            m_opcodecon = Opcode_LE;
        else if (opcodePosStr == "none")
            m_opcodecon = Opcode_None;
        else
            throw new HookExeption(info, QString("Invalid branch condition \"%1\"").arg(info->get("cond")));
    }
    else
        m_opcodecon = Opcode_None;
}

void SoftBranchHook::writeData(FileBase* file, quint32 extraDataPtr)
{
    file->seek(m_address - 0x00100000);
    quint32 originalOpcode = file->read32();            // This breaks position dependent opcodes
    file->seek(m_address - 0x00100000);
    file->write32(makeBranchOpcode(m_address, extraDataPtr, false, m_opcodecon));

    file->seek(extraDataPtr - 0x00100000);
    if (m_opcodePos == Opcode_Pre) file->write32(offsetOpcode(originalOpcode, m_address, file->pos() + 0x00100000));
    file->write32(0xE92D5FFF);      //push {r0-r12, r14}
    file->write32(makeBranchOpcode(file->pos() + 0x00100000, m_destination, true, m_opcodecon));
    file->write32(0xE8BD5FFF);      //pop {r0-r12, r14}
    if (m_opcodePos == Opcode_Post) file->write32(offsetOpcode(originalOpcode, m_address, file->pos() + 0x00100000));
    file->write32(makeBranchOpcode(file->pos() + 0x00100000, m_address + 4, false, m_opcodecon));
}


PatchHook::PatchHook(HookLinker* parent, HookInfo* info)
{
    base(parent, info);

    if (info->has("data"))
    {
        fromBin = false;

        QString dataStr = info->get("data").toLower();
        if (dataStr.startsWith("0x"))
            dataStr = dataStr.mid(2);

        dataStr.replace(' ',  "");
        dataStr.replace('\t', "");

        m_patchData = QByteArray::fromHex(dataStr.toLatin1());
    }
    else if (info->has("src") && info->has("len"))
    {
        fromBin = true;

        if (!parent->symTable())
            throw new HookExeption(info, "Invalid SymTable");

        bool ok;
        m_src = parent->symTable()->get(info->get("src"), &ok);

        if (!ok)
            throw new HookExeption(info, "Invalid src symbol");

        m_len = info->getUint("len", &ok);

        if (!ok)
            throw new HookExeption(info, "Invalid length");


    }
    else
        throw new HookExeption(info, "No patch data given");
}

void PatchHook::writeData(FileBase* file, quint32)
{
    if (!fromBin)
    {
        file->seek(m_address - 0x00100000);
        file->writeData((quint8*)m_patchData.data(), m_patchData.size());
    }
    else
    {
        file->seek(m_src - 0x00100000);
        quint8* writeData = new quint8[m_len];
        file->readData(writeData, m_len);

        file->seek(m_address - 0x00100000);
        file->writeData(writeData, m_len);
        delete[] writeData;
    }
}


SymbolAddrPatchHook::SymbolAddrPatchHook(HookLinker* parent, HookInfo* info)
{
    base(parent, info);

    QString symKey = "sym";

    if (!info->has(symKey))
        throw new HookExeption(info, "No symbol given");

    bool ok;
    m_destination = parent->symTable()->get(info->get(symKey), &ok);

    if (!ok)
        throw new HookExeption(info, QString("Symbol name \"%1\" not found").arg(info->get(symKey)));
}

void SymbolAddrPatchHook::writeData(FileBase* file, quint32)
{
    file->seek(m_address - 0x00100000);
    file->write32(m_destination);
}
