#include "cabb.h"
#include <windows.h>

void main()
{
	Cabbage cab;
	cab.EnCabFile("e:\\1.zip", "e:\\2.zip");
	cab.DeCabFile("e:\\2.zip", "e:\\3.zip");
}