#pragma once
#include "..\in.h"

namespace offsets
{
	namespace game
	{
		inline uintptr_t notifyservercert = 0x784D6C0;
		inline uintptr_t tryapplicationquit = 0x1D5FFF0;
		inline uintptr_t tryapplicationquit2 = 0x1D5FE70;
		inline uintptr_t fatalapplcationquit = 0x1D596F0;
		inline uintptr_t logouttobootscene = 0x1D5CB30;
		inline uintptr_t logouttobootsceneasync = 0x1D5CA70;
	}



	namespace movement
	{
		inline uintptr_t get_isflyingenabled = 0x173DD90;
	}
	
	namespace clothing
	{
		inline uintptr_t get_isitemunlockedloccaly = 0x12A4E50;
		inline uintptr_t get_isavataritemunlocked = 0x12A4BC0;
		inline uintptr_t isavataritemunlocked = 0x12A4B60;
		inline uintptr_t get_isavataritemalredypurchased = 0x12A4930;
		inline uintptr_t isavataritemalredypurchased = 0x12A4A60;

	}

	namespace inventory
	{
		inline uintptr_t get_canusestreamingcamera = 0xD09A50;
		inline uintptr_t get_canusestreamcam = 0x1ED5F80;
		inline uintptr_t get_canuseconsumables = 0x209C3C0;
		inline uintptr_t get_canusesharecamera = 0xBA1230;
		inline uintptr_t get_canuseclothingcustomizer = 0xBA6FB0;
		inline uintptr_t doeslocalplayerownkey1 = 0xCE5C80;
		inline uintptr_t doeslocalplayerownkey2 = 0xCE5DE0;
	}

	namespace player
	{
		inline uintptr_t get_isdeveloper = 0x1D62460;
		inline uintptr_t get_fieldofview = 0x9A58CC0;
	}

	namespace combat
	{
		inline uintptr_t get_isoncooldown = 0x1CD4FE0;
	}
}