:: Clean output directories
rmdir obj\Debug /s /q
rmdir bin\Debug /s /q

:: Compile folders
"%Wix%\bin\heat.exe" dir .\Scripts -cg Scripts -ag -srd -dr SCRIPTSFOLDER -out SCRIPTS.wxs
"%Wix%\bin\heat.exe" dir .\Installs -cg Installs -ag -srd -dr INSTALLSFOLDER -out INSTALLS.wxs
"%Wix%\bin\heat.exe" dir .\Common -cg Common -ag -srd -dr COMMONFOLDER -out Common.wxs -t Common.xslt

:: Make the MSI
"%Wix%\bin\candle.exe" -out obj\Debug\ -arch x64 Product.wxs SCRIPTS.wxs INSTALLS.wxs Common.wxs
"%Wix%\bin\light.exe" -out bin\Debug\Update_Toast-1-0.msi obj\Debug\Product.wixobj obj\debug\Common.wixobj obj\debug\Scripts.wixobj obj\debug\Installs.wixobj -b Common -b Scripts -b Installs