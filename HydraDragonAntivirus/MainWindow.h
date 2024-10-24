#ifndef MAINWINDOW_H
#define MAINWINDOW_H


#include <FilePanel.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Window.h>
#include <string>
#include <set>
#include <Path.h>
#include <Message.h>
#include <String.h>

class MainWindow : public BWindow
{
public:
							MainWindow();
	virtual					~MainWindow();

	virtual void			MessageReceived(BMessage* msg);
    virtual void            RefsReceived(BMessage* message); // Declaration of RefsReceived

    // Function declarations
    void StartMonitoring();
    void MonitorDesktop();
    void CheckFilesInDirectory(const std::string& directory, std::set<std::string>& processedFiles);
    void InstallClamAV(); // Function to install ClamAV
    void ChangeMonitorDirectory();
    void CreateConfigDirectory();
    void UpdateConfigFile(const BPath& selectedPath);

    BString monitoringDirectory; // Member variable to store the monitoring directory

private:
			BMenuBar*		_BuildMenu();

			status_t		_LoadSettings(BMessage& settings);
			status_t		_SaveSettings();

			BMenuItem*		fSaveMenuItem;
			BFilePanel*		fOpenPanel;
			BFilePanel*		fSavePanel;
            BFilePanel*     fSelectPanel;
};

#endif
