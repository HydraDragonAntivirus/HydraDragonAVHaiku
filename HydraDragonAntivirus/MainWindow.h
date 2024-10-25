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
#include <CheckBox.h> // Include for BCheckBox
#include <ListView.h> // Include for BListView (or BFileListView if you're using that)

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
    void ShowAlert(const std::string& title, const std::string& message);
    void LogQuarantineDetails(const std::string& logFilePath, const std::string& filePath, const std::string& reason, bool isPUA);
    bool IsClamDRunning();
    void StartScan();
    void CreateScanControls();

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

    // Checkboxes to enable/disable engines
    BCheckBox* fRansomwareCheckBox;  // Check for ransomware engine
    BCheckBox* fYaraCheckBox;         // Check for YARA engine
    BCheckBox* fClamAVCheckBox;       // Check for ClamAV engine
    BCheckBox* fAutoQuarantineCheckBox; // Checkbox for auto quarantine feature

    BButton* fScanButton;             // Button to start scanning
    BButton* fStopButton;             // Button to stop scanning
    BButton* fQuarantineButton;       // Button to quarantine a detected item
    BButton* fRemoveButton;           // Button to remove a detected item
    BButton* fIgnoreButton;           // Button to ignore a detected item
    BButton* fQuarantineAllButton;    // Button to quarantine all detected items
    BButton* fRemoveAllButton;        // Button to remove all detected items
    BButton* fIgnoreAllButton;        // Button to ignore all detected items
    BButton* fSelectDirectoryButton;   // Button to select scan directory

    void _Quarantine(const std::string& filePath);  // Method to handle quarantine action
    void _Remove(const std::string& filePath);  // Method to handle removal action
    void _Ignore(const std::string& filePath); // Method to handle ignore action
    void _QuarantineAll();             // Declaration for the Quarantine All action
    void _RemoveAll();                 // Method to handle remove all action
    void _IgnoreAll();                 // Method to handle ignore all action
    void NormalScan(const std::string& directory, std::set<std::string>& processedFiles);
    void StopScan();

    // Engine states
    bool clamavEnabled;
    bool yaraEnabled;
    bool ransomwareEnabled;

    bool isMonitoring = false;  // Track if monitoring is active
    std::thread monitoringThread; // Store the thread reference

    // Add missing member variables and constants
    BTextView* fStatusView;  // For status updates in the UI
    YR_RULES* rules;         // For YARA rules

    std::set<std::string> exclusions; // For storing exclusion rules

    std::string GetSelectedFilePath(); // Function to get the selected file path
    std::set<std::string> GetSelectedFilePaths(); // Function to get selected file paths

    // File List View to display files
    BListView* fFileListView; // Change this to BFileListView if needed

    // Function to check ClamAV installation
    bool IsClamAVInstalled();

    bool isScanning = false; // Track if a scan is in progress

    // Helper function to get matched YARA rule
    std::string GetMatchedRule();  // Declaration of GetMatchedRule
};

#endif
