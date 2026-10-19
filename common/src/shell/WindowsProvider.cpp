#include "WindowsProvider.h"
#ifdef WINDOWS
#include "LocalShell.h"
#include "utils/StringUtils.h"
#include "platform/PlatformHelper.h"
#include <Windows.h>
#include <Aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <array>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace {
constexpr wchar_t Guid[] = L"{74A23DE2-B81D-46EC-E129-CD32507ED716}";
constexpr wchar_t ProviderValue[] = L"win_pulseunlock";
constexpr wchar_t RegPath[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{74A23DE2-B81D-46EC-E129-CD32507ED716}";
constexpr wchar_t ClsPath[] = L"SOFTWARE\\Classes\\CLSID\\{74A23DE2-B81D-46EC-E129-CD32507ED716}";
constexpr wchar_t InprocPath[] = L"SOFTWARE\\Classes\\CLSID\\{74A23DE2-B81D-46EC-E129-CD32507ED716}\\InprocServer32";
constexpr size_t PayloadLimit = 64u * 1024u * 1024u;
constexpr size_t JournalLimit = 16u * 1024u;
constexpr std::array<const wchar_t*,4> Keys{RegPath,ClsPath,InprocPath,InprocPath};
constexpr std::array<const wchar_t*,4> Names{L"",L"",L"",L"ThreadingModel"};
struct Value { const wchar_t* key{}; const wchar_t* name{}; bool exists{}; DWORD type{}; std::vector<BYTE> data; };

DWORD LastErrorCode() { DWORD e=GetLastError(); return e ? e : ERROR_GEN_FAILURE; }
bool Fail(const char* stage, DWORD code=0) {
  const DWORD error=code ? code : LastErrorCode();
  LocalShell::FailOperation(stage,error);
  SetLastError(error);
  return false;
}
std::filesystem::path Dir() { wchar_t p[MAX_PATH]{}; UINT n=GetSystemDirectoryW(p,MAX_PATH); if(!n||n>=MAX_PATH) throw GetLastError(); return std::filesystem::path(p)/L"PulseUnlock"; }
std::filesystem::path Journal() { return Dir()/L"provider.journal"; }
std::filesystem::path LockPath() { return Dir()/L"provider.lock"; }
bool Hash(const BYTE* data,size_t size,std::array<BYTE,32>& out) {
  BCRYPT_ALG_HANDLE alg{}; BCRYPT_HASH_HANDLE hash{}; DWORD objectSize{}, got{}; std::vector<BYTE> object;
  NTSTATUS s=BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0);
  if(s>=0) s=BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&objectSize),sizeof(objectSize),&got,0);
  if(s>=0) { object.resize(objectSize); s=BCryptCreateHash(alg,&hash,object.data(),objectSize,nullptr,0,0); }
  if(s>=0) s=BCryptHashData(hash,const_cast<PUCHAR>(data),static_cast<ULONG>(size),0);
  if(s>=0) s=BCryptFinishHash(hash,out.data(),static_cast<ULONG>(out.size()),0);
  if(hash) BCryptDestroyHash(hash); if(alg) BCryptCloseAlgorithmProvider(alg,0); return s>=0;
}
bool Resource(std::vector<BYTE>& bytes) { HRSRC r=FindResourceW(nullptr,MAKEINTRESOURCEW(101),MAKEINTRESOURCEW(10)); if(!r)return false; DWORD n=SizeofResource(nullptr,r); HGLOBAL g=LoadResource(nullptr,r); auto p=g?static_cast<const BYTE*>(LockResource(g)):nullptr; if(!p||!n||n>PayloadLimit)return false; bytes.assign(p,p+n); return true; }
std::wstring Hex(const std::array<BYTE,32>& h) { static constexpr wchar_t digits[]=L"0123456789abcdef"; std::wstring s; s.reserve(64); for(BYTE b:h){s.push_back(digits[b>>4]);s.push_back(digits[b&15]);} return s; }
std::filesystem::path PayloadPath(const std::array<BYTE,32>& h) { return Dir()/(L"provider-"+Hex(h)+L".dll"); }
bool ReadValue(Value& v) {
 HKEY h{}; LONG e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,v.key,0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&h); if(e==ERROR_FILE_NOT_FOUND)return true; if(e!=ERROR_SUCCESS)return Fail("provider-registry-open",e);
 DWORD n=0; e=RegQueryValueExW(h,v.name,nullptr,&v.type,nullptr,&n); if(e==ERROR_FILE_NOT_FOUND){RegCloseKey(h);return true;} if(e!=ERROR_SUCCESS||n>4096){RegCloseKey(h);return Fail("provider-registry-size",e==ERROR_SUCCESS?ERROR_INVALID_DATA:e);}
 v.data.resize(n); e=RegQueryValueExW(h,v.name,nullptr,&v.type,v.data.data(),&n); RegCloseKey(h); if(e!=ERROR_SUCCESS)return Fail("provider-registry-read",e); v.data.resize(n);v.exists=true;return true;
}
bool ReadAll(std::array<Value,4>& a) { for(size_t i=0;i<a.size();++i){a[i].key=Keys[i];a[i].name=Names[i];if(!ReadValue(a[i]))return false;}return true; }
bool Equal(const Value&a,const Value&b) { return a.exists==b.exists&&(!a.exists||(a.type==b.type&&a.data==b.data)); }
bool WriteValue(const Value& v) {
 if(!v.exists && wcscmp(v.key,RegPath)==0) {
   HKEY key{};
   LONG e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,RegPath,0,KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS|KEY_WOW64_64KEY,&key);
   if(e==ERROR_FILE_NOT_FOUND) return true;
   if(e!=ERROR_SUCCESS) { SetLastError(e); return false; }
   DWORD values{},subkeys{};
   e=RegQueryInfoKeyW(key,nullptr,nullptr,nullptr,&subkeys,nullptr,nullptr,&values,nullptr,nullptr,nullptr,nullptr);
   wchar_t name[2]{}; DWORD length=2;
   if(e==ERROR_SUCCESS && values==1) e=RegEnumValueW(key,0,name,&length,nullptr,nullptr,nullptr,nullptr);
   RegCloseKey(key);
   if(e!=ERROR_SUCCESS || subkeys || values>1 || (values==1 && length!=0)) { SetLastError(ERROR_ALREADY_EXISTS); return false; }
   e=RegDeleteKeyExW(HKEY_LOCAL_MACHINE,RegPath,KEY_WOW64_64KEY,0);
   if(e!=ERROR_SUCCESS && e!=ERROR_FILE_NOT_FOUND) { SetLastError(e); return false; }
   HKEY parent{};
   e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&parent);
   if(e==ERROR_SUCCESS) { e=RegFlushKey(parent); RegCloseKey(parent); }
   if(e!=ERROR_SUCCESS) { SetLastError(e); return false; }
   return true;
 }
 HKEY h{}; LONG e=RegCreateKeyExW(HKEY_LOCAL_MACHINE,v.key,0,nullptr,0,KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&h,nullptr); if(e!=ERROR_SUCCESS){SetLastError(e);return false;}
 if(v.exists)e=RegSetValueExW(h,v.name,0,v.type,v.data.empty()?nullptr:v.data.data(),static_cast<DWORD>(v.data.size())); else { e=RegDeleteValueW(h,v.name); if(e==ERROR_FILE_NOT_FOUND)e=ERROR_SUCCESS; }
 if(e==ERROR_SUCCESS)e=RegFlushKey(h); RegCloseKey(h); if(e!=ERROR_SUCCESS){SetLastError(e);return false;}return true;
}
Value StringValue(size_t i,const std::wstring& s) { Value v{Keys[i],Names[i],true,REG_SZ,{}}; auto p=reinterpret_cast<const BYTE*>(s.c_str());v.data.assign(p,p+(s.size()+1)*sizeof(wchar_t));return v; }
bool String(const Value &v, std::wstring &out) {
  if(!v.exists || v.type != REG_SZ || v.data.size() < sizeof(wchar_t) || v.data.size()%sizeof(wchar_t)) return false;
  out.resize(v.data.size()/sizeof(wchar_t));
  memcpy(out.data(), v.data.data(), v.data.size());
  if(out.back()!=L'\0') return false;
  out.pop_back();
  return out.find(L'\0') == std::wstring::npos;
}
bool OwnedPath(const std::wstring &s) {
  auto p=std::filesystem::path(s);
  auto system=Dir().parent_path();
  if(p==system/L"win_pulseunlock.dll" || p==system/L"win-pcbiounlock.dll") return true;
  auto name=p.filename().wstring();
  return p.parent_path()==Dir() && name.size()==77 && name.starts_with(L"provider-") && name.ends_with(L".dll") &&
    std::all_of(name.begin()+9,name.begin()+73,[](wchar_t c){return (c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f');});
}
bool Owned(const std::array<Value,4> &v) {
  for(size_t i=0;i<4;++i) {
    if(!v[i].exists) continue;
    std::wstring s;
    if(!String(v[i],s)) return false;
    if(i<2 && s!=ProviderValue) return false;
    if(i==2 && !OwnedPath(s)) return false;
    if(i==3 && s!=L"Apartment") return false;
  }
  return true;
}
std::array<Value,4> Desired(const std::filesystem::path& payload) { return {StringValue(0,ProviderValue),StringValue(1,ProviderValue),StringValue(2,payload.wstring()),StringValue(3,L"Apartment")}; }
// Inspect security on the object actually opened, never a second pathname lookup.
bool TrustedSid(PSID sid) {
  if(IsWellKnownSid(sid,WinLocalSystemSid) || IsWellKnownSid(sid,WinBuiltinAdministratorsSid)) return true;
  PSID installer{};
  if(!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",&installer)) return false;
  const bool trusted=EqualSid(sid,installer)!=FALSE;
  LocalFree(installer);
  return trusted;
}
bool ValidateSecurity(HANDLE h,bool secret) {
  PSID owner{}; PACL acl{}; PSECURITY_DESCRIPTOR descriptor{};
  const DWORD error=GetSecurityInfo(h,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                                  &owner,nullptr,&acl,nullptr,&descriptor);
  if(error!=ERROR_SUCCESS) { SetLastError(error); return Fail("provider-acl-read",error); }
  bool ok=owner && IsValidSid(owner) && TrustedSid(owner) && acl && IsValidAcl(acl);
  bool system=false,admin=false;
  GENERIC_MAPPING mapping{FILE_GENERIC_READ,FILE_GENERIC_WRITE,FILE_GENERIC_EXECUTE,FILE_ALL_ACCESS};
  for(DWORD i=0;ok && i<acl->AceCount;++i) {
    void *entry{};
    if(!GetAce(acl,i,&entry)) { ok=false; break; }
    const auto ace=static_cast<ACCESS_ALLOWED_ACE*>(entry);
    // Reject unfamiliar/conditional ACEs rather than guessing their semantics.
    if(ace->Header.AceType!=ACCESS_ALLOWED_ACE_TYPE) { ok=false; break; }
    auto sid=reinterpret_cast<PSID>(&ace->SidStart);
    if(!IsValidSid(sid)) { ok=false; break; }
    DWORD mask=ace->Mask;
    MapGenericMask(&mask,&mapping);
    const bool trusted=TrustedSid(sid);
    const DWORD readOnly=FILE_GENERIC_READ|FILE_GENERIC_EXECUTE;
    if(!trusted && (secret || (mask & ~readOnly))) { ok=false; break; }
    if(!(ace->Header.AceFlags & INHERIT_ONLY_ACE) && (mask & FILE_GENERIC_READ)==FILE_GENERIC_READ) {
      if(IsWellKnownSid(sid,WinLocalSystemSid)) system=true;
      if(IsWellKnownSid(sid,WinBuiltinAdministratorsSid)) admin=true;
    }
  }
  LocalFree(descriptor);
  if(ok && system && admin) return true;
  SetLastError(ERROR_ACCESS_DENIED);
  return Fail("provider-acl-policy",ERROR_ACCESS_DENIED);
}
struct HeldFile {
  HANDLE h{INVALID_HANDLE_VALUE};
  ~HeldFile(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
};
bool ReadFile(const std::filesystem::path& path,std::vector<BYTE>& bytes,size_t limit,DWORD share=FILE_SHARE_READ,HeldFile* retained=nullptr) {
 LocalShell::StoragePathGuard guard(path);
 if(!guard.IsValid()) return Fail("provider-file-identity",ERROR_ACCESS_DENIED);
 if(path.parent_path()==Dir()) {
   HeldFile directory;
   directory.h=CreateFileW(Dir().c_str(),READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
   if(directory.h==INVALID_HANDLE_VALUE || !ValidateSecurity(directory.h,false)) return false;
 }
 HANDLE h=CreateFileW(path.c_str(),GENERIC_READ|READ_CONTROL,share,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr); if(h==INVALID_HANDLE_VALUE)return false;
 BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
 bool ok=GetFileInformationByHandle(h,&info) && info.nNumberOfLinks==1 &&
         !(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)) &&
         GetFileSizeEx(h,&size) && size.QuadPart>=0 && static_cast<ULONGLONG>(size.QuadPart)<=limit;
 if(!ok) SetLastError(ERROR_FILE_INVALID);
 if(ok) ok=ValidateSecurity(h,limit==JournalLimit);
 if(ok){bytes.resize(static_cast<size_t>(size.QuadPart));size_t at=0;while(at<bytes.size()){DWORD chunk=static_cast<DWORD>(std::min<size_t>(bytes.size()-at,1u<<20)),got{};if(!::ReadFile(h,bytes.data()+at,chunk,&got,nullptr)||!got){ok=false;SetLastError(ERROR_READ_FAULT);break;}at+=got;}}
 const DWORD error=GetLastError();
 if(ok && retained) retained->h=h; else CloseHandle(h);
 SetLastError(error);return ok;
}
bool WriteNew(const std::filesystem::path& path,const std::vector<BYTE>& bytes,bool journal) {
 PSECURITY_DESCRIPTOR sd{};
 const auto policy=journal ? L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" :
                            L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)";
 if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(policy,SDDL_REVISION_1,&sd,nullptr)) return false;
 SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
 HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE|READ_CONTROL,0,&sa,CREATE_NEW,
                      FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_WRITE_THROUGH,nullptr);
 const DWORD openError=GetLastError(); LocalFree(sd);
 if(h==INVALID_HANDLE_VALUE) { SetLastError(openError); return false; }
 bool ok=ValidateSecurity(h,journal);
 size_t at=0;
 while(ok && at<bytes.size()) {
   DWORD chunk=static_cast<DWORD>(std::min<size_t>(bytes.size()-at,1u<<20)),put{};
   if(!WriteFile(h,bytes.data()+at,chunk,&put,nullptr)||!put) { ok=false; SetLastError(ERROR_WRITE_FAULT); break; }
   at+=put;
 }
 if(ok) ok=FlushFileBuffers(h)!=FALSE;
 const DWORD error=GetLastError(); CloseHandle(h);
 if(!ok) DeleteFileW(path.c_str());
 SetLastError(error);return ok;
}
bool PublishPayload(const std::filesystem::path &destination,const std::vector<BYTE> &bytes) {
  auto suffix=StringUtils::RandomString(24,false);
  if(suffix.empty()) return false;
  auto temporary=Dir()/(L"payload-"+std::wstring(suffix.begin(),suffix.end())+L".tmp");
  if(!WriteNew(temporary,bytes,false)) return false;
  std::vector<BYTE> verify;
  bool ok=ReadFile(temporary,verify,PayloadLimit) && verify==bytes;
  if(ok) ok=MoveFileExW(temporary.c_str(),destination.c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE;
  if(!ok) DeleteFileW(temporary.c_str());
  return ok;
}
bool PublishJournal(const std::vector<BYTE> &bytes) {
  auto suffix=StringUtils::RandomString(24,false);
  if(suffix.empty()) return false;
  auto temporary=Dir()/(L"journal-"+std::wstring(suffix.begin(),suffix.end())+L".tmp");
  if(!WriteNew(temporary,bytes,true)) return false;
  std::vector<BYTE> verify;
  bool ok=ReadFile(temporary,verify,JournalLimit) && verify==bytes;
  if(ok) ok=MoveFileExW(temporary.c_str(),Journal().c_str(),MOVEFILE_WRITE_THROUGH)!=FALSE;
  if(!ok) DeleteFileW(temporary.c_str());
  return ok;
}
bool EnsureSecureDirectory() {
  auto d = Dir();
  LocalShell::StoragePathGuard ancestry(d.parent_path());
  if(!ancestry.IsValid()) return Fail("provider-directory-parent", ERROR_ACCESS_DENIED);
  PSECURITY_DESCRIPTOR sd{};
  if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
       L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)", SDDL_REVISION_1, &sd, nullptr)) return false;
  SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
  bool ok = CreateDirectoryW(d.c_str(), &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
  if(ok) {
    LocalShell::StoragePathGuard guard(d);
    ok = guard.IsValid();
    HANDLE h = ok ? CreateFileW(d.c_str(), READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) : INVALID_HANDLE_VALUE;
    if(h == INVALID_HANDLE_VALUE) ok = false;
    else {
      BY_HANDLE_FILE_INFORMATION info{};
      PACL acl{}; BOOL present{}, defaulted{};
      ok = GetFileInformationByHandle(h, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && ValidateSecurity(h,false) &&
           GetSecurityDescriptorDacl(sd, &present, &acl, &defaulted) && present &&
           SetSecurityInfo(h, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                           nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS;
      if(ok) ok=ValidateSecurity(h,false);
      CloseHandle(h);
    }
  }
  LocalFree(sd);
  return ok;
}
bool Serialize(const std::array<Value,4>& old,const std::array<Value,4>& desired,std::vector<BYTE>& b) {
 b={'P','U','J','2'};for(const auto* group:{&old,&desired})for(const auto&v:*group){b.push_back(v.exists?1:0);for(int j=0;j<4;++j)b.push_back(static_cast<BYTE>(v.type>>(j*8)));DWORD n=static_cast<DWORD>(v.data.size());for(int j=0;j<4;++j)b.push_back(static_cast<BYTE>(n>>(j*8)));b.insert(b.end(),v.data.begin(),v.data.end());if(b.size()>JournalLimit)return false;}return true;
}
bool Deserialize(const std::vector<BYTE>& b,std::array<Value,4>& old,std::array<Value,4>& desired) {
 if(b.size()<8||b.size()>JournalLimit||memcmp(b.data(),"PUJ2",4))return false;size_t p=4;auto read=[&](std::array<Value,4>& a){for(size_t i=0;i<4;++i){if(p+9>b.size())return false;a[i].key=Keys[i];a[i].name=Names[i];BYTE ex=b[p++];if(ex>1)return false;a[i].exists=ex!=0;a[i].type=0;for(int j=0;j<4;++j)a[i].type|=DWORD(b[p++])<<(8*j);DWORD n=0;for(int j=0;j<4;++j)n|=DWORD(b[p++])<<(8*j);if(n>4096||p+n>b.size()||(!a[i].exists&&n))return false;a[i].data.assign(b.begin()+p,b.begin()+p+n);p+=n;}return true;};return read(old)&&read(desired)&&p==b.size();
}
bool ValidatePayload(const std::filesystem::path& path,HeldFile &held) {
  if(!OwnedPath(path.wstring())) return Fail("provider-payload-path",ERROR_INVALID_DATA);
  std::vector<BYTE> bytes;
  if(!ReadFile(path,bytes,PayloadLimit,FILE_SHARE_READ,&held)) return Fail("provider-payload-read",LastErrorCode());
  if(bytes.empty()) return Fail("provider-payload-empty",ERROR_INVALID_DATA);
  // Legacy bytes have no recorded trusted digest; validate location, identity
  // and permissions, but do not claim cryptographic authenticity.
  if(path.parent_path()==Dir().parent_path()) return true;
  std::array<BYTE,32> hash{};
  if(!Hash(bytes.data(),bytes.size(),hash) || path.filename()!=PayloadPath(hash).filename())
    return Fail("provider-payload-hash",ERROR_FILE_INVALID);
  return true;
}
bool Restore(const std::array<Value,4>& old,const std::array<Value,4>& desired) {
  std::array<Value,4> cur{};
  if(!ReadAll(cur)) return false;
  for(size_t i=0;i<4;++i) {
    if(i==0 && !cur[i].exists) continue; // valid interrupted disabled-activation phase
    if(!Equal(cur[i],old[i]) && !Equal(cur[i],desired[i])) return false;
  }
  Value disabled{Keys[0],Names[0],false,0,{}};
  if(!WriteValue(disabled)) return false;
  HeldFile payload;
  std::unique_ptr<LocalShell::StoragePathGuard> payloadGuard;
  if(old[0].exists) {
    if(!std::all_of(old.begin(),old.end(),[](const Value &v){return v.exists;}) || !Owned(old))
      return Fail("provider-recovery-registration",ERROR_INVALID_DATA);
    std::wstring path;
    if(!String(old[2],path)) return Fail("provider-recovery-path",ERROR_INVALID_DATA);
    payloadGuard=std::make_unique<LocalShell::StoragePathGuard>(std::filesystem::path(path));
    if(!payloadGuard->IsValid()) return Fail("provider-recovery-ancestry",ERROR_ACCESS_DENIED);
    if(!ValidatePayload(path,payload)) return false; // activation stays disabled; keep journal
  }
  for(size_t i=1;i<4;++i) if(!WriteValue(old[i])) return false;
  if(!WriteValue(old[0])) return false;
  std::array<Value,4> check{};
  if(!ReadAll(check)) return false;
  for(size_t i=0;i<4;++i) if(!Equal(check[i],old[i])) return false;
  return true;
}
bool Recover() {
 std::vector<BYTE>b;if(!ReadFile(Journal(),b,JournalLimit)){return GetLastError()==ERROR_FILE_NOT_FOUND;}
 std::array<Value,4> old{},desired{};
 if(!Deserialize(b,old,desired)||!Owned(old)||!Owned(desired))return Fail("provider-journal-invalid",ERROR_INVALID_DATA);
 if(!Restore(old,desired))return false;
 return DeleteFileW(Journal().c_str())||GetLastError()==ERROR_FILE_NOT_FOUND;
}
struct Lock {
  HANDLE h{INVALID_HANDLE_VALUE};
  explicit Lock(bool) {
    PSECURITY_DESCRIPTOR sd{};
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",SDDL_REVISION_1,&sd,nullptr)) return;
    SECURITY_ATTRIBUTES sa{sizeof(sa),sd,FALSE};
    h=CreateFileW(LockPath().c_str(),GENERIC_READ|GENERIC_WRITE|READ_CONTROL,0,&sa,OPEN_ALWAYS,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    LocalFree(sd);
    if(h!=INVALID_HANDLE_VALUE) {
      BY_HANDLE_FILE_INFORMATION info{};
      if(!GetFileInformationByHandle(h,&info) || info.nNumberOfLinks!=1 ||
         (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) || !ValidateSecurity(h,true)) {
        CloseHandle(h); h=INVALID_HANDLE_VALUE;
      }
    }
  }
  ~Lock(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
  bool ok()const{return h!=INVALID_HANDLE_VALUE;}
};
bool ClearUserDefaults() {
  HKEY key{};
  LONG e=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI\\UserTile",0,KEY_QUERY_VALUE|KEY_SET_VALUE|KEY_WOW64_64KEY,&key);
  if(e==ERROR_FILE_NOT_FOUND) return true;
  if(e!=ERROR_SUCCESS) return Fail("provider-defaults-open",e);
  DWORD index=0;
  for(;;) {
    wchar_t name[256]{}; BYTE data[512]{}; DWORD nameSize=256, size=sizeof(data), type{};
    e=RegEnumValueW(key,index,name,&nameSize,nullptr,&type,data,&size);
    if(e==ERROR_NO_MORE_ITEMS) break;
    if(e==ERROR_MORE_DATA) { ++index; continue; }
    if(e!=ERROR_SUCCESS) { RegCloseKey(key); return Fail("provider-defaults-enumerate",e); }
    Value value{nullptr,nullptr,true,type,{data,data+size}}; std::wstring text;
    if(String(value,text) && _wcsicmp(text.c_str(),Guid)==0) {
      e=RegDeleteValueW(key,name);
      if(e!=ERROR_SUCCESS) { RegCloseKey(key); return Fail("provider-defaults-delete",e); }
    } else ++index;
  }
  e=RegFlushKey(key); RegCloseKey(key);
  return e==ERROR_SUCCESS || Fail("provider-defaults-flush",e);
}
}
namespace WindowsProvider {
bool IsInstalled() {
  LocalShell::ClearOperationError();
  try {
    std::array<Value,4> values{};
    if(!ReadAll(values)) return false; // ReadValue preserves the exact registry error.
    if(std::none_of(values.begin(),values.end(),[](const Value &v){return v.exists;})) return false;
    if(!std::all_of(values.begin(),values.end(),[](const Value &v){return v.exists;}) || !Owned(values))
      return Fail("provider-probe-registration",ERROR_INVALID_DATA);
    std::wstring registeredPath;
    if(!String(values[2],registeredPath)) return Fail("provider-probe-path",ERROR_INVALID_DATA);
    HeldFile payload;
    return ValidatePayload(std::filesystem::path(registeredPath),payload);
  } catch(...) { return Fail("provider-probe",ERROR_GEN_FAILURE); }
}
bool Install() {
 LocalShell::ClearOperationError();try{
 if(!LocalShell::IsRunningAsAdmin())return Fail("provider-admin",ERROR_ACCESS_DENIED);
 if(!EnsureSecureDirectory())return Fail("provider-directory");LocalShell::StoragePathGuard guard(Dir());if(!guard.IsValid())return Fail("provider-path-guard");Lock lock(true);if(!lock.ok())return Fail("provider-lock");if(!Recover())return Fail("provider-recovery");
 std::vector<BYTE> payload;if(!Resource(payload))return Fail("provider-resource");std::array<BYTE,32> hash{};if(!Hash(payload.data(),payload.size(),hash))return Fail("provider-hash");auto dll=PayloadPath(hash);
 HANDLE existing=CreateFileW(dll.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
 if(existing!=INVALID_HANDLE_VALUE){CloseHandle(existing);std::vector<BYTE> found;if(!ReadFile(dll,found,PayloadLimit)||found!=payload)return Fail("provider-payload-collision",ERROR_FILE_INVALID);}else if(GetLastError()==ERROR_FILE_NOT_FOUND){if(!PublishPayload(dll,payload))return Fail("provider-payload-create");}else return Fail("provider-payload-open");
 HeldFile installedPayload;
 LocalShell::StoragePathGuard payloadGuard(dll);
 if(!payloadGuard.IsValid() || !ValidatePayload(dll,installedPayload)) return Fail("provider-install-payload",LastErrorCode());
 std::array<Value,4> old{};if(!ReadAll(old))return Fail("provider-registry-snapshot");
 if(!Owned(old)) return Fail("provider-registration-conflict",ERROR_ALREADY_EXISTS);
 auto desired=Desired(dll); // journal contains old and intended exact values before any registry mutation
 std::vector<BYTE> journal;if(!Serialize(old,desired,journal)||!PublishJournal(journal))return Fail("provider-journal-create");
 bool ok=true;
 // Activation disabled first, then class/InprocServer32, activation enabled last.
 Value disabled=desired[0];disabled.exists=false;if(!WriteValue(disabled))ok=false;
 if(ok&&!WriteValue(desired[1]))ok=false;if(ok&&!WriteValue(desired[2]))ok=false;if(ok&&!WriteValue(desired[3]))ok=false;if(ok&&!WriteValue(desired[0]))ok=false;
 if(ok){std::array<Value,4> verify{};ok=ReadAll(verify);for(size_t i=0;ok&&i<4;++i)ok=Equal(verify[i],desired[i]);}
 if(!ok){DWORD original=LastErrorCode();if(!Recover())return Fail("provider-rollback",original);return Fail("provider-install",original);}
 if(!DeleteFileW(Journal().c_str())){DWORD original=LastErrorCode();if(!Recover())return Fail("provider-rollback",original);return Fail("provider-journal-delete",original);}return true;
 }catch(...){return Fail("provider-install",ERROR_GEN_FAILURE);}
}
bool Remove() {
  LocalShell::ClearOperationError();
  try {
    if(!LocalShell::IsRunningAsAdmin()) return Fail("provider-admin",ERROR_ACCESS_DENIED);
    if(!EnsureSecureDirectory()) return Fail("provider-directory");
    LocalShell::StoragePathGuard guard(Dir());
    if(!guard.IsValid()) return Fail("provider-path-guard");
    Lock lock(true);
    if(!lock.ok()) return Fail("provider-lock");
    if(!Recover()) return Fail("provider-recovery");
    std::array<Value,4> old{}, absent{};
    if(!ReadAll(old) || !Owned(old)) return Fail("provider-remove-conflict",ERROR_INVALID_DATA);
    for(size_t i=0;i<4;++i) absent[i]={Keys[i],Names[i],false,0,{}};
    std::vector<BYTE> journal;
    if(!Serialize(old,absent,journal) || !PublishJournal(journal)) return Fail("provider-journal-create");
    bool ok=true;
    for(size_t i=0;i<4 && ok;++i) ok=WriteValue(absent[i]);
    if(!ok) {
      auto error=LastErrorCode();
      if(!Recover()) return Fail("provider-remove-rollback",error);
      return Fail("provider-remove-values",error);
    }
    // WriteValue(absent[0]) already removed and flushed the activation key.
    // Do not perform a second path-based deletion after committing the journal.
    if(!DeleteFileW(Journal().c_str())) return Fail("provider-journal-delete");
    // Leave old/loaded DLLs inert rather than deleting a module used by LogonUI.
    return ClearUserDefaults();
  } catch(...) { return Fail("provider-remove",ERROR_GEN_FAILURE); }
}
}
#endif
