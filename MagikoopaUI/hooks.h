#ifndef HOOKS_H
#define HOOKS_H

#include "symtable.h"
#include "Filesystem/filesystem.h"

#include <exception>
#include <QByteArray>

class HookLinker;
class HookInfo;

// Extradata | Code | Symbols

class Hook
{
public:
    virtual ~Hook();

    virtual void writeData(FileBase*, quint32) {}

    virtual quint32 extraDataSize() { return 0; }

protected:
    Hook() {}
    void base(HookLinker* parent, HookInfo* info);

    static quint32 makeBranchOpcode(quint32 src, quint32 dest, bool link, quint32 condition);
    static quint32 offsetOpcode(quint32 opcode, quint32 orgPosition, qint32 newPosition);

    QString m_name;
    quint32 m_address;
    QByteArray m_data;

    HookLinker* m_parent;
    HookInfo* m_info;
};


class BranchHook : public Hook
{
public:
    BranchHook(HookLinker* parent, HookInfo* info);
    void writeData(FileBase* file, quint32 extraDataPos);

private:
    enum Opcode_Con 
    { 
        Opcode_EQ, 
        Opcode_NE, 
        Opcode_CS, 
        Opcode_CC, 
        Opcode_MI, 
        Opcode_PL, 
        Opcode_VS, 
        Opcode_VC,
        Opcode_HI,
        Opcode_LS,
        Opcode_GE,
        Opcode_LT,
        Opcode_GT,
        Opcode_LE,
        Opcode_None
    };

    Opcode_Con m_opcodecon;
    bool m_link;
    quint32 m_destination;
};

class SoftBranchHook : public Hook
{
public:
    SoftBranchHook(HookLinker* parent, HookInfo* info);
    void writeData(FileBase* file, quint32 extraDataPtr);
    quint32 extraDataSize() { return 5*4; }

private:
    enum Opcode_Pos { Opcode_Ignore, Opcode_Pre, Opcode_Post };
    enum Opcode_Con 
    { 
        Opcode_EQ, 
        Opcode_NE, 
        Opcode_CS, 
        Opcode_CC, 
        Opcode_MI, 
        Opcode_PL, 
        Opcode_VS, 
        Opcode_VC,
        Opcode_HI,
        Opcode_LS,
        Opcode_GE,
        Opcode_LT,
        Opcode_GT,
        Opcode_LE,
        Opcode_None
    };

    Opcode_Pos m_opcodePos;
    Opcode_Con m_opcodecon;
    quint32 m_destination;
};


class PatchHook : public Hook
{
public:
    PatchHook(HookLinker* parent, HookInfo* info);
    void writeData(FileBase* file, quint32 extraDataPos);

private:
    QByteArray m_patchData;
    quint32 m_src;
    quint32 m_len;
    bool fromBin;
};


class SymbolAddrPatchHook : public Hook
{
public:
    SymbolAddrPatchHook(HookLinker* parent, HookInfo* info);
    void writeData(FileBase* file, quint32 extraDataPos);

private:
    quint32 m_destination;
};


#endif // HOOKS_H
