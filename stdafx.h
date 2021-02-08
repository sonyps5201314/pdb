// <copyright file="stdafx.h" company="Microsoft Corporation">
// Copyright (C) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license. See LICENSE.txt in the project root for license information.
// </copyright>

#pragma once

#include "targetver.h"

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <crtdbg.h>
#include <comip.h>
#include <comdef.h>
#include <comutil.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

#include <Setup.Configuration.h>
#include "Helpers.h"

//JKSDK
#define __DO_NOT_USE_JKSDK_OUTPUTDEBUGSTRING__
//#define __DO_NOT_USE_JKSDK_TRACE__
//#define __DO_NOT_USE_JKSDK_ASSERT__
//#define __DO_NOT_USE_COM__
//#define __DO_NOT_USE_ATL_CSTRING__
#define __DO_NOT_USE_JKSDK_CDLG__
#define __DO_NOT_USE_JKSDK_AUTOLOCK__
#define __DO_NOT_USE_JKSDK_SHOWCALLSTACKTRACK_SOURCEFILEPATHMAPPINGS__
#include "F:\MyCppProjects\JKSDK\Lib\JKSDK.H"

#include <atlenc.h>