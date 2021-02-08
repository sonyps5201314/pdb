// <copyright file="stdafx.cs" company="Microsoft Corporation">
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt in the project root for license information.
// </copyright>

#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

//JKSDK
#include "F:\MyCppProjects\JKSDK\Lib\JKSDK.CPP"
#ifdef _M_IX86
#pragma comment(lib,"F:\\MyCppProjects\\JKSDK\\Lib\\JKSDK_ASM_LIB.lib")
#elif defined(_M_AMD64)
#pragma comment(lib,"F:\\MyCppProjects\\JKSDK\\Lib\\x64\\JKSDK_ASM_LIB.lib")
#endif