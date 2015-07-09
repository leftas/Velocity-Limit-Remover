#pragma once
#include "include.h"
#ifndef LOG_H_
#define LOG_H_
class Log
{
public:
	enum Type{
		Normal,
		Debug,
		Error,
		FatalError
	};
	static void Log::Init(bool CreateConsole = false);
	static void Log::Write(Log::Type type, const char* fmt, ...);
private:
	static bool s_bConsole;
};
#endif