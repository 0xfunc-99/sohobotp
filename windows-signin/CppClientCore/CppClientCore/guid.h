/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

// GUID of primary Credential Provider: the key holding its settings and history.
// SohobOTP: {B3D2C6A1-5E7F-4C21-9A6E-0D4F5C8B7A31}, the same as CLSID_CSample in
// CredentialProvider\guid.h, the installer and the agent (multiOTP's own id, {FCEFDFAB-...},
// sent the program folder, portal address and timeouts to a key that does not exist: the
// sign-in screen then started c:\multiotp\multiotp.exe, "file not found"). CI checks both match.
DEFINE_GUID(CLSID_Multiotp,
	0xb3d2c6a1, 0x5e7f, 0x4c21, 0x9a, 0x6e, 0x0d, 0x4f, 0x5c, 0x8b, 0x7a, 0x31);


// ADD ADDITIONAL HERE