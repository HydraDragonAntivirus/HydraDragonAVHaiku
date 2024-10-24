#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <FilePanel.h>
#include <MenuBar.h>
#include <MenuItem.h>
#include <Window.h>
#include <TextView.h>  // For BTextView
#include <Alert.h>     // For BAlert
#include <string>
#include <set>
#include <Path.h>
#include <Message.h>
#include <String.h>
#include <thread>

#include <yara.h>

class MainWindow : public BWindow
{
public:
    MainWindow();
    virtual ~MainWindow();

    virtual void MessageReceived(BMessage* msg);
    virtual void RefsReceived(BMessage* message); // Declaration of RefsReceived

    // Function declarations
    void StartMonitoring();
    void MonitorDesktop();
    void CheckFilesInDirectory(const std::string& directory, std::set<std::string>& processedFiles);
    void InstallClamAV(); // Function to install ClamAV
    void ChangeMonitorDirectory();
    void CreateConfigDirectory();
    void UpdateConfigFile(const BPath& selectedPath);
    void ActivateClamAV();
    void StartClamAVMonitoring();
    void StopClamAVMonitoring(); // Stop ClamAV monitoring
    void MonitorClamAV();
    void UpdateVirusDefinitions();
    void ActivateYARA();
    void StopMonitoring();  // Method to stop monitoring
    std::set<std::string> LoadExclusionRules(const std::string& filePath);

    BString monitoringDirectory; // Member variable to store the monitoring directory

private:
    BMenuBar* _BuildMenu();

    status_t _LoadSettings(BMessage& settings);
    status_t _SaveSettings();

    BMenuItem* fSaveMenuItem;
    BFilePanel* fOpenPanel;
    BFilePanel* fSavePanel;
    BFilePanel* fSelectPanel;
    
    bool isMonitoring = false;  // Track if monitoring is active
    std::thread monitoringThread; // Store the thread reference

    // Add missing member variables and constants
    BTextView* fStatusView;  // For status updates in the UI
    YR_RULES* rules;         // For YARA rules

    std::set<std::string> exclusions; // For storing exclusion rules

    // Define message constants
    enum {
        kMsgStartMonitor = 'stmo',
        kMsgStopMonitor = 'spmo',
        kMsgStartClamAVMonitor = 'stcm',
        kMsgStopClamAVMonitor = 'spcm',
        kMsgCheckClamAVInstallation = 'chci'
    };

    // Function to check ClamAV installation
    bool IsClamAVInstalled();

    // Helper function to get matched YARA rule
    std::string GetMatchedRule();  // Declaration of GetMatchedRule
};

#endif
