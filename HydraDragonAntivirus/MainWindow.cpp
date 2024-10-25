// TODO: Auto Remove or Continue customazation can be added here or ask user etc. also you need do this for normal malware scanner after you stop malware or not via clamav remove yara remove but not for ransom remove, Optimization no multiple detections add kill mechanism before move quarantine  add full scan quick scan add clamav with kill then quarantime remove form list after quarantine or delete file how many detected etc. 
#include "MainWindow.h"
#include "KnownExtensions.h"
#include "QuarantineManager.h"

#include <Application.h>
#include <Catalog.h>
#include <File.h>
#include <FindDirectory.h>
#include <LayoutBuilder.h>
#include <Menu.h>
#include <MenuBar.h>
#include <Path.h>
#include <View.h>
#include <cstdlib>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <chrono>     // For std::chrono
#include <set>
#include <fstream> // For file handling
#include <thread>
#include <FilePanel.h> // Include this for file dialogs
#include <Alert.h>
#include <string>
#include <yara.h>
#include <cstdio>
#include <iostream>
#include <ScrollView.h>
#include <CheckBox.h> // Include for BCheckBox
#include <ListView.h>

#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "Window"
#define MAX_PATH_LENGTH 255

// Message constants
static const uint32 kMsgStartMonitor = 'strt';
static const uint32 kMsgStopMonitor = 'spmo';
static const uint32 kMsgQuitApp = 'quit';
static const uint32 kMsgInstallClamAV = 'inst';
static const uint32 kMsgChangeMonitorDirectory = 'chmd';
static const uint32 kMsgActivateClamAV = 'actv';
static const uint32 kMsgStartClamAVMonitor = 'clam'; // New message for ClamAV monitoring
static const uint32 kMsgStopClamAVMonitor = 'spcm';
static const uint32 kMsgCheckClamAVInstallation = 'chci';
static const uint32 kMsgUpdateVirusDefinitions = 'updt';
static const uint32 kMsgActivateYara = 'acty'; // New message for YARA activation
static const uint32 kMsgOpenQuarantineManager = 'oqmt'; // Message for opening the Quarantine Manager

// Messages for user actions
static const uint32 kMsgStartScan = 'stsc'; // Message for starting a scan
static const uint32 kMsgStopScan = 'stps'; // Message for stopping a scan
static const uint32 kMsgQuarantineAll = 'qral'; // Message for quarantining all threats
static const uint32 kMsgIgnoreAll = 'igal'; // Message for ignoring all threats
static const uint32 kMsgRemove = 'dlte'; // Message for deleting a selected threat
static const uint32 kMsgDRemoveAll = 'dall'; // Message for deleting all threats
static const uint32 kMsgRansomwareCheck = 'rchk'; // Message for enabling/disabling ransomware check
static const uint32 kMsgYaraCheck = 'ychk'; // Message for enabling/disabling YARA engine
static const uint32 kMsgClamAVCheck = 'cchk'; // Message for enabling/disabling ClamAV engine
static const uint32 kMsgAutoQuarantineCheck = 'aQnt'; // Message for enabling/disabling auto quarantine
static const uint32 kMsgQuarantine = 'qurn';             // Message for quarantining a detected threat
static const uint32 kMsgIgnore = 'igor';                  // Message for ignoring a detected threat
static const uint32 kMsgSelectDirectory = 'seld';        // Message for selecting a directory
static const uint32 kMsgFileListViewSelection = 'flsv'; // Message for selecting an item in the file list view

static const char* kSettingsFile = "Hydra Dragon Antivirus Settings";

// List of known file extensions
std::vector<std::string> KnownExtensions = getKnownExtensions();

MainWindow::MainWindow() 
    : BWindow(BRect(100, 100, 500, 400), B_TRANSLATE("Hydra Dragon Antivirus"), B_TITLED_WINDOW,
              B_ASYNCHRONOUS_CONTROLS | B_QUIT_ON_WINDOW_CLOSE)
{
    isScanning(false); // Initialize the scanning flag
    // Initialize the file panel for directory selection
    fSelectPanel = new BFilePanel(B_OPEN_PANEL, new BMessenger(this), NULL, B_DIRECTORY_NODE, false);

    CreateConfigDirectory(); // Create the config directory

    // Load exclusion rules
    std::set<std::string> exclusions = LoadExclusionRules("excluded/excluded_rules.txt");  // Use forward slash

    BMenuBar* menuBar = _BuildMenu();

    // Create a scroll view for better status display
    fStatusView = new BTextView("statusView");
    fStatusView->MakeEditable(false); // Make it read-only
    fStatusView->SetText("Status:\n"); // Initialize with a default message
    fStatusView->SetFontSize(12); // Set font size for better readability

    // Create the scroll view, passing ownership of fStatusView
    BScrollView* scrollView = new BScrollView("scrollView", fStatusView,
                                               B_FOLLOW_ALL_SIDES, 
                                               false,  // Do not horizontal scroll
                                               true);   // Enable vertical scroll

    // Checkboxes for enabling scan engines
    fRansomwareCheckBox = new BCheckBox("ransomwareCheck", "Enable Ransomware Check", new BMessage('rchk'));
    fYaraCheckBox = new BCheckBox("yaraCheck", "Enable YARA Engine", new BMessage('ychk'));
    fClamAVCheckBox = new BCheckBox("clamavCheck", "Enable ClamAV Engine", new BMessage('cchk'));
    fAutoQuarantineCheckBox = new BCheckBox("autoQuarantineCheckBox", "Enable Auto Quarantine", new BMessage('aQnt'));

    // Scan button
    fScanButton = new BButton("scanButton", "Scan", new BMessage('scan'));

    // Quarantine buttons
    fQuarantineAllButton = new BButton("quarantineAllButton", "Quarantine All", new BMessage('qral'));
    fIgnoreAllButton = new BButton("ignoreAllButton", "Ignore All", new BMessage('igal'));
    fRemoveButton = new BButton("removeButton", "Remove", new BMessage('dlte'));
    fRemoveAllButton = new BButton("removeAllButton", "Remove All", new BMessage('dall'));

    // Directory selection button
    BButton* fSelectDirectoryButton = new BButton("selectDirectoryButton", "Select Directory", new BMessage('seld'));

    // Create the file list view for displaying detected threats
    fFileListView = new BListView("fileListView");
    fFileListView->SetSelectionMessage(new BMessage('flsv')); // Set a message for item selection

    // Create a scroll view for the file list view
    BScrollView* fileListScrollView = new BScrollView("fileListScrollView", fFileListView,
                                                       B_FOLLOW_LEFT | B_FOLLOW_TOP,
                                                       true,  // Enable horizontal scroll
                                                       true);  // Enable vertical scroll

    // Set the layout
    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(menuBar)
        .Add(scrollView)
        .Add(fileListScrollView) // Add the file list view scroll
        .Add(fRansomwareCheckBox)  // Add the ransomware check checkbox
        .Add(fYaraCheckBox)        // Add the YARA check checkbox
        .Add(fClamAVCheckBox)      // Add the ClamAV check checkbox
        .Add(fScanButton)          // Add the Scan button
        .Add(fQuarantineAllButton) // Add the Quarantine All button
        .Add(fIgnoreAllButton)     // Add the Ignore All button
        .Add(fRemoveButton)        // Add the Remove button
        .Add(fRemoveAllButton)     // Add the Remove All button
        .Add(fSelectDirectoryButton) // Add the Select Directory button
        .AddGlue()
        .End();

    BMessenger messenger(this);

    BMessage settings;
    _LoadSettings(settings);

    // Load the default monitoring directory from settings
    const char* defaultMonitorDir = nullptr;
    if (settings.FindString("monitor_directory", &defaultMonitorDir) == B_OK) {
        monitoringDirectory = defaultMonitorDir; // Store the selected directory
    } else {
        // If not found, default to the Desktop path
        BPath desktopPath;
        find_directory(B_DESKTOP_DIRECTORY, &desktopPath);
        monitoringDirectory = desktopPath.Path(); // Set to Desktop
    }

    BRect frame;
    if (settings.FindRect("main_window_rect", &frame) == B_OK) {
        MoveTo(frame.LeftTop());
        ResizeTo(frame.Width(), Bounds().Height());
    }
    MoveOnScreen();
}

MainWindow::~MainWindow()
{
    _SaveSettings();
    delete fSelectPanel;  // Clean up the file panel
}

BMenuBar* MainWindow::_BuildMenu()
{
    BMenuBar* menuBar = new BMenuBar("menubar");
    BMenu* menu;
    BMenuItem* item;

    // 'Monitor' Menu
    menu = new BMenu(B_TRANSLATE("Monitor"));
    item = new BMenuItem(B_TRANSLATE("Change Monitor Directory"), new BMessage(kMsgChangeMonitorDirectory));
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Start Ransomware Monitoring"), new BMessage(kMsgStartMonitor), 'C');
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Stop Ransomware Monitoring"), new BMessage(kMsgStopMonitor), 'S');
    menu->AddItem(item); // Add item for stopping ransomware monitoring

    item = new BMenuItem(B_TRANSLATE("Start ClamAV And YARA Monitoring"), new BMessage(kMsgStartClamAVMonitor), 'A');
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Stop ClamAV And YARA Monitoring"), new BMessage(kMsgStopClamAVMonitor), 'Z');
    menu->AddItem(item); // Add item for stopping ClamAV and YARA monitoring

    item = new BMenuItem(B_TRANSLATE("Quit"), new BMessage(kMsgQuitApp), 'Q');
    menu->AddItem(item);
    menuBar->AddItem(menu);

    // 'Engine' Menu
    menu = new BMenu(B_TRANSLATE("Engine")); // New Engine menu

    item = new BMenuItem(B_TRANSLATE("Activate ClamAV"), new BMessage(kMsgActivateClamAV));
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Activate YARA"), new BMessage(kMsgActivateYara));
    menu->AddItem(item);

    menuBar->AddItem(menu); // Add Engine menu to menuBar

    // 'Installation' Menu
    menu = new BMenu(B_TRANSLATE("Installation"));
    item = new BMenuItem(B_TRANSLATE("Install ClamAV"), new BMessage(kMsgInstallClamAV));
    menu->AddItem(item);
    
    // New item to check if ClamAV is installed
    item = new BMenuItem(B_TRANSLATE("Check ClamAV Installation"), new BMessage(kMsgCheckClamAVInstallation));
    menu->AddItem(item);
    
    menuBar->AddItem(menu); // Add Installation menu to menuBar

    // 'Update' Menu
    menu = new BMenu(B_TRANSLATE("Update")); // New Update menu
    item = new BMenuItem(B_TRANSLATE("Update Virus Definitions"), new BMessage(kMsgUpdateVirusDefinitions));
    menu->AddItem(item);
    menuBar->AddItem(menu); // Add Update menu to menuBar

    // 'Quarantine' Menu
    menu = new BMenu(B_TRANSLATE("Quarantine"));
    item = new BMenuItem(B_TRANSLATE("Open Quarantine Manager"), new BMessage('oqmt'));
    menu->AddItem(item);
    menuBar->AddItem(menu); // Add Quarantine menu to menuBar

    // 'Help' Menu
    menu = new BMenu(B_TRANSLATE("Help"));
    item = new BMenuItem(B_TRANSLATE("About" B_UTF8_ELLIPSIS), new BMessage(B_ABOUT_REQUESTED));
    item->SetTarget(be_app);
    menu->AddItem(item);
    menuBar->AddItem(menu); // Add Help menu to menuBar

    return menuBar;
}

void MainWindow::MessageReceived(BMessage* message)
{
    switch (message->what) {
    case kMsgStartMonitor:
        StartMonitoring();
        break;

    case kMsgStopMonitor: // Handle stopping ransomware monitoring
        StopMonitoring();
        break;

    case kMsgStartClamAVMonitor:
        StartClamAVMonitoring();
        break;

    case kMsgStopClamAVMonitor: // Handle stopping ClamAV and YARA monitoring
        StopClamAVMonitoring();
        break;

    case kMsgQuitApp: {
        // Cleanup YARA rules if they were loaded
        if (rules != nullptr) {
            yr_rules_destroy(rules);
            rules = nullptr; // Set to nullptr to avoid dangling pointer
        }

        // Kill the clamd process using system call
        int result = system("kill clamd"); // Kills instance of clamd
        if (result == 0) {
            printf("Successfully sent kill command to clamd.\n");
        } else {
            perror("Failed to kill clamd");
        }

        // Optionally, notify the user or log that the application is closing
        printf("Cleaning up resources and quitting the application...\n");

        // Request the application to quit
        PostMessage(B_QUIT_REQUESTED);
        break;
    }

    case kMsgInstallClamAV:
        InstallClamAV();
        break;

    case kMsgActivateClamAV: // Handle ClamAV activation
        ActivateClamAV();
        break;

    case kMsgChangeMonitorDirectory:
        ChangeMonitorDirectory();
        break;

    case B_REFS_RECEIVED:
        RefsReceived(message);
        break;

    case kMsgUpdateVirusDefinitions:
        UpdateVirusDefinitions();
        break;

    case kMsgOpenQuarantineManager: {
        QuarantineManager* qManager = new QuarantineManager();
        qManager->Show();
        break;
    }

    case kMsgActivateYara: // Handle YARA activation
        ActivateYARA();
        break;

    case kMsgCheckClamAVInstallation: {
        if (IsClamAVInstalled()) {
            BAlert* alert = new BAlert("ClamAV Check", 
                                       "ClamAV is installed.", 
                                       "OK");
            alert->Go();  // Display success message
        } else {
            BAlert* alert = new BAlert("ClamAV Check", 
                                       "ClamAV is not installed.", 
                                       "OK");
            alert->Go();  // Display failure message
        }
        break;
    }

    case kMsgStartScan: {
        std::set<std::string> processedFiles;
        isScanning(true); // Update the scanning flag
        NormalScan(monitoringDirectory.String(), processedFiles); // Start normal scan
        break;
    }

    case kMsgStopScan: {
        // Call the function to stop the scan
        StopScan(); // Implement this method to handle stopping the scan
        break;
    }

    case kMsgQuarantine: {
        // Get the selected file path from the list
        std::string selectedFilePath = GetSelectedFilePath(); // Implement this function to retrieve the selected file path
        if (!selectedFilePath.empty()) {
            _Quarantine(selectedFilePath); // Pass the selected file path
        }
        break;
    }

    case kMsgIgnore: {
        // Get the selected file path from the list
        std::string selectedFilePath = GetSelectedFilePath(); // Implement this function to retrieve the selected file path
        if (!selectedFilePath.empty()) {
            _Ignore(selectedFilePath); // Pass the selected file path
        }
        break;
    }

    case kMsgRemove: {
        // Get the selected file path from the list
        std::string selectedFilePath = GetSelectedFilePath(); // Implement this function to retrieve the selected file path
        if (!selectedFilePath.empty()) {
            _Remove(selectedFilePath); // Pass the selected file path
        }
        break;
    }

    case kMsgQuarantineAll: {
        _QuarantineAll();
        break;
    }

    case kMsgIgnoreAll: {
        _IgnoreAll();
        break;
    }

    case kMsgRemoveAll: {
        _RemoveAll();
        break;
    }

    case kMsgRansomwareCheck: {
        // Handle enabling/disabling ransomware check
        ransomwareEnabled = !ransomwareEnabled; // Toggle state
        printf("Ransomware check %s\n", ransomwareEnabled ? "enabled" : "disabled");
        break;
    }

    case kMsgYaraCheck: {
        // Handle enabling/disabling YARA engine
        yaraEnabled = !yaraEnabled; // Toggle state
        printf("YARA engine %s\n", yaraEnabled ? "enabled" : "disabled");
        break;
    }

    case kMsgClamAVCheck: {
        // Handle enabling/disabling ClamAV engine
        clamavEnabled = !clamavEnabled; // Toggle state
        printf("ClamAV engine %s\n", clamavEnabled ? "enabled" : "disabled");
        break;
    }

    case kMsgAutoQuarantineCheck: {
        // Handle enabling/disabling auto quarantine
        bool autoQuarantineEnabled = message->FindBool("value", false);
        printf("Auto quarantine %s\n", autoQuarantineEnabled ? "enabled" : "disabled");
        break;
    }

    case kMsgFileListViewSelection: {
        // Handle the selection of a file in the file list view
        std::string selectedFilePath = GetSelectedFilePath(); // Implement this function to retrieve the selected file path
        if (!selectedFilePath.empty()) {
            // For example, you might want to update a status view or take some action based on the selection
            printf("File selected: %s\n", selectedFilePath.c_str());
        }
        break;
    }

    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void MainWindow::StartMonitoring()
{
    if (!isMonitoring) { // Check if not already monitoring
        BAlert* alert = new BAlert("Warning", 
                                   "Ransomware monitoring is starting. Any detected ransomware activity will result in an immediate shutdown for security.",
                                   "OK", "Cancel", nullptr, B_WIDTH_AS_USUAL, B_WARNING_ALERT);
        int32 response = alert->Go(); // Show the alert and get the user's response

        if (response == 1) { // If user clicks "Cancel" (second button)
            return; // Do not start monitoring
        }

        printf("Monitoring started\n");
        fStatusView->Insert("Ransomware monitoring started.\n"); // Update status view
        isMonitoring = true; // Set monitoring state
        monitoringThread = std::thread(&MainWindow::MonitorDesktop, this);
        monitoringThread.detach(); // Detach the thread to run independently
    }
}

void MainWindow::StopMonitoring()
{
    if (isMonitoring) { // Check if currently monitoring
        printf("Monitoring stopped\n");
        fStatusView->Insert("Ransomware monitoring stopped.\n"); // Update status view
        isMonitoring = false; // Update monitoring state
        monitoringThread.join();
    }
}

bool MainWindow::IsClamAVInstalled() {
    // Execute the clamscan command to check if ClamAV is installed
    int result = system("command -v clamscan > /dev/null 2>&1");
    
    // Check the result: 0 indicates the command exists (ClamAV is installed)
    return (result == 0);
}

void MainWindow::StartClamAVMonitoring()
{
    // Check if ClamD is running at the start
    if (!IsClamDRunning()) {
        BAlert* alert = new BAlert("ClamAV Not Running",
                                   "The ClamAV daemon (clamd) is not running. Please start it before monitoring.",
                                   "OK");
        alert->Go(); // Show the alert and wait for user response
        return; // Exit the function if clamd is not running
    }

    // Check if YARA rules are loaded
    if (rules == nullptr) {
        BAlert* alert = new BAlert("YARA Rules Not Loaded",
                                   "YARA rules are not loaded. Please load the rules before starting monitoring.",
                                   "OK");
        alert->Go(); // Show the alert and wait for user response
        return; // Exit the function if YARA rules are not loaded
    }

    // Notify about automatic quarantine mechanism
    BAlert* alert = new BAlert("Automatic Quarantine",
                                "Please note that there is an automatic quarantine mechanism in place. "
                                "Ensure that you start both the YARA and ClamAV engines before continuing.",
                                "OK");
    alert->Go(); // Show the alert and wait for user response

    printf("ClamAV Monitoring started\n");
    fStatusView->Insert("ClamAV monitoring started.\n"); // Update status view

    std::thread clamAVThread(&MainWindow::MonitorClamAV, this);
    clamAVThread.detach(); // Detach the thread to run independently
}

void MainWindow::StopClamAVMonitoring()
{
    // Cleanup YARA rules if they were loaded
    if (rules != nullptr) {
        yr_rules_destroy(rules);
        rules = nullptr; // Set to nullptr to avoid dangling pointer
        printf("YARA rules have been cleaned up.\n");
    }

    // Kill the clamd process using system call
    int result = system("kill clamd"); // Kills instance of clamd
    if (result == 0) {
        printf("Successfully sent kill command to clamd.\n");
    } else {
        perror("Failed to kill clamd");
    }

    // Update status view
    fStatusView->Insert("ClamAV monitoring stopped.\n");

    // Display alert
    BAlert* alert = new BAlert("Monitoring Stopped", 
                               "ClamAV and YARA monitoring has been stopped.", 
                               "OK", nullptr, nullptr, 
                               B_WIDTH_AS_USUAL, B_WARNING_ALERT);
    alert->Go();
}

void MainWindow::CreateConfigDirectory() {
    BPath configPath;
    status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &configPath);
    if (status != B_OK) {
        printf("Error finding user settings directory\n");
        return;
    }

    // Append HydraDragonAntivirus directory name
    configPath.Append("HydraDragonAntivirus");

    // Ensure the parent directory exists
    BDirectory configDir(configPath.Path());
    if (configDir.InitCheck() != B_OK) {
        if (create_directory(configPath.Path(), 0755) != B_OK) {
            printf("Error creating config directory: %s\n", configPath.Path());
        } else {
            printf("Config directory created: %s\n", configPath.Path());
        }
    } else {
        printf("Config directory already exists: %s\n", configPath.Path());
    }
}

void MainWindow::UpdateConfigFile(const BPath& selectedPath) {
    // Get the path to the user settings directory
    BPath configPath;
    if (find_directory(B_USER_SETTINGS_DIRECTORY, &configPath) != B_OK) {
        printf("Error finding user settings directory\n");
        return;
    }

    // Append the application-specific folder and config file name
    configPath.Append("HydraDragonAntivirus/config.txt");

    // Open the config file for writing
    BFile configFile(configPath.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
    if (configFile.InitCheck() != B_OK) {
        printf("Error opening config file for writing: %s\n", configPath.Path());
        return;
    }

    // Write the selected directory to the config file
    BString newPath(selectedPath.Path());
    ssize_t bytesWritten = configFile.Write(newPath.String(), newPath.Length());
    if (bytesWritten != (ssize_t)newPath.Length()) {
        printf("Error writing to config file\n");
    } else {
        printf("Configuration file updated with directory: %s\n", newPath.String());
    }
}

void MainWindow::ChangeMonitorDirectory()
{
    // Set the file panel's target to this window
    fSelectPanel->SetTarget(this);
    fSelectPanel->Show();
}

void MainWindow::RefsReceived(BMessage* message)
{
    entry_ref ref;
    if (message->FindRef("refs", &ref) == B_OK) {
        BPath path(&ref);
        
        // Update the configuration with the selected path
        UpdateConfigFile(path);

        // Show an alert to confirm the directory change
        BAlert* alert = new BAlert("Directory Changed",
                                   "The monitoring directory has been updated.",
                                   "OK", NULL, NULL, B_WIDTH_AS_USUAL, B_INFO_ALERT);
        alert->Go();
    }
}

void MainWindow::ActivateYARA() {
    printf("Activating YARA...\n");

    // Check if the compiled_rule.yrc file exists
    std::string yaraRulesPath = "compiled_rule.yrc"; // Update with the actual path
    if (!std::filesystem::exists(yaraRulesPath)) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "YARA rules file not found.", 
                                   "OK", nullptr, nullptr, 
                                   B_WIDTH_AS_USUAL, B_INFO_ALERT);
        alert->Go();
        return; // Exit if file does not exist
    }

    // Initialize YARA
    if (yr_initialize() != ERROR_SUCCESS) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "Failed to initialize YARA.", 
                                   "OK", nullptr, nullptr, 
                                   B_WIDTH_AS_USUAL, B_WARNING_ALERT);
        alert->Go();
        return; // Exit if initialization fails
    }

    // Load YARA rules
    YR_RULES* rules = nullptr;
    if (yr_rules_load(yaraRulesPath.c_str(), &rules) != ERROR_SUCCESS) {
        BAlert* alert = new BAlert("YARA Activation", 
                                   "Failed to load YARA rules.", 
                                   "OK", nullptr, nullptr, 
                                   B_WIDTH_AS_USUAL, B_WARNING_ALERT);
        alert->Go();
        yr_finalize();
        return; // Exit if loading rules fails
    }

    // Inform the user of the result
    BAlert* alert = new BAlert("YARA Activation", 
                               "YARA rules activated successfully.", 
                               "OK", nullptr, nullptr, 
                               B_WIDTH_AS_USUAL, B_INFO_ALERT);
    alert->Go();
}

void MainWindow::ActivateClamAV() {
    printf("Activating ClamAV...\n");

    // Check if ClamAV is installed
    if (!IsClamAVInstalled()) {
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "ClamAV is not installed. Please install it first.", 
                                   "OK");
        alert->Go();  // Display message
        return; // Exit if ClamAV is not installed
    }

    // Warn the user that starting ClamAV may take some time
    BAlert* warnAlert = new BAlert("ClamAV Activation", 
                                   "Activating ClamAV may take some time. Please wait...", 
                                   "OK");
    warnAlert->Go();  // Display warning message

    // Start the clamd daemon
    int result = system("clamd"); 

    if (result == 0) {
        // Successful start
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "ClamAV daemon activated successfully.", 
                                   "OK");
        alert->Go();  // Display success message
    } else {
        // Failed to start
        BAlert* alert = new BAlert("ClamAV Activation", 
                                   "Failed to activate ClamAV daemon.", 
                                   "OK");
        alert->Go();  // Display failure message
    }
}

void MainWindow::UpdateVirusDefinitions()
{
    printf("Updating virus definitions...\n");

    // Run freshclam to update the virus definitions
    int result = system("freshclam");

    // Check the result and inform the user
    if (result == 0) {
        BAlert* alert = new BAlert("Update Successful", 
                                   "Virus definitions updated successfully.", 
                                   "OK");
        alert->Go();
    } else {
        BAlert* alert = new BAlert("Update Failed", 
                                   "Failed to update virus definitions.", 
                                   "OK");
        alert->Go();
    }
}

void MainWindow::InstallClamAV() {
    // Check if ClamAV is already installed
    bool isInstalled = IsClamAVInstalled();
    
    // Show a warning message before starting the installation
    BAlert* warningAlert = new BAlert("Warning", 
                                      "The installation process may take some time. Do you want to proceed with the installation?", 
                                      "Cancel", 
                                      "OK");

    // Display the warning alert and check the user's response
    int32 buttonIndex = warningAlert->Go();
    if (buttonIndex == 0) {
        // User chose to cancel the installation
        return;
    }

    // Inform user whether they are reinstalling or installing for the first time
    if (isInstalled) {
        BAlert* reinstallAlert = new BAlert("Reinstall ClamAV", 
                                             "ClamAV is already installed. Do you want to reinstall it?", 
                                             "No", 
                                             "Yes");
        // Check the user's choice about reinstallation
        int32 reinstallIndex = reinstallAlert->Go();
        if (reinstallIndex == 0) {
            // User chose not to reinstall
            return;
        }
    }

    printf("Installing ClamAV...\n");

    // Install ClamAV without confirmation
    system("pkgman install -y clamav"); 

    // Copy clamavconfig/freshclam.conf to /boot/system/settings/clamav/
    system("cp -f clamavconfig/freshclam.conf /boot/system/settings/clamav/");

    // Copy clamavconfig/clamd.conf to /boot/system/settings/clamav/
    system("cp -f clamavconfig/clamd.conf /boot/system/settings/clamav/");

    // Copy the db folder to the ClamAV settings directory
    system("cp -rf db /boot/system/settings/clamav");

    // Run freshclam to update the virus definitions
    system("freshclam");

    // Show a message box at the end of the process
    BAlert* alert = new BAlert("ClamAV Installation", 
                               "ClamAV installation and setup completed successfully.", 
                               "OK");
    alert->Go();  // Display the message box
}

// Function to load exclusion rules from a file
std::set<std::string> MainWindow::LoadExclusionRules(const std::string& filePath) {
    std::set<std::string> exclusions;
    std::ifstream file(filePath);
    
    if (!file.is_open()) {
        printf("Error opening exclusion rules file: %s\n", filePath.c_str());
        return exclusions; // Return empty set on error
    }

    std::string line;
    while (std::getline(file, line)) {
        // Optionally trim whitespace from the line
        line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());
        
        if (!line.empty()) {
            exclusions.insert(line); // Add the rule to the set
        }
    }

    file.close();
    return exclusions;
}

bool MainWindow::IsClamDRunning() {
    // Check if the ClamAV daemon is running using the `ps` command
    int result = system("ps | grep -w clamd | grep -v grep > /dev/null 2>&1");

    // The command returns 0 if the process is found, 1 if not found
    return (result == 0);
}

void MainWindow::ShowAlert(const std::string& title, const std::string& message) {
    BAlert* alert = new BAlert(title.c_str(), message.c_str(), "OK");
    alert->Go(); // Show the alert; this will be non-blocking in a thread
}

void MainWindow::MonitorClamAV() {
    // Set the quarantine directory within the user settings directory
    BPath quarantinePath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
    quarantinePath.Append("HydraDragonAntivirus/Quarantine");

    // Create the quarantine directory if it doesn't exist
    if (!std::filesystem::exists(quarantinePath.Path())) {
        std::filesystem::create_directories(quarantinePath.Path());
    }

    // Set to track processed files
    std::set<std::string> processedFiles; 
    std::string monitorDir = monitoringDirectory.String(); // Convert BString to std::string

    // Define path for the quarantine log
    BPath configPath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &configPath);
    configPath.Append("HydraDragonAntivirus/quarantine_log.txt");

    while (true) {
        // Get the list of files in the directory
        std::vector<std::string> currentFiles;
        for (const auto& entry : std::filesystem::directory_iterator(monitorDir)) {
            if (entry.is_regular_file()) {
                currentFiles.push_back(entry.path().string());
            }
        }

        // Scan only new files
        for (const auto& file : currentFiles) {
            if (processedFiles.find(file) == processedFiles.end() && file.find(quarantinePath.Path()) == std::string::npos) {
                // If the file hasn't been processed yet and is not in the quarantine folder, scan it with ClamAV
                std::string clamScanCommand = "clamdscan --no-summary " + file;
                
                // Use popen to execute the command and read output
                FILE* pipe = popen(clamScanCommand.c_str(), "r");
                if (!pipe) {
                    perror("popen failed");
                    continue; // Skip this file and move on
                }

                char buffer[128];
                std::string output;
                while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    output += buffer; // Collect output from the command
                }
                int result = pclose(pipe); // Close the pipe and get the exit code

                std::string virusName;

                if (result != 0) {
                    // Check if the output contains "FOUND"
                    if (output.find("FOUND") != std::string::npos) {
                        // Extract virus name from the output
                        virusName = output.substr(0, output.find(" FOUND")); // Get the part before "FOUND"
                    }
                }

                if (virusName.empty()) {
                    // The scan was successful and the file is clean
                    processedFiles.insert(file); // Mark this file as processed
                } else {
                    // Check if the detected virus is a PUA
                    bool isPUA = virusName.rfind("PUA", 0) == 0; // Check if virusName starts with "PUA"
                    std::string type = isPUA ? "PUA" : "Virus"; // Set type based on check

                    // Notify the user about the detected threat
                    std::string alertMessage = type + " detected: " + virusName + " in file: " + file;
                    fStatusView->Insert(alertMessage.c_str()); // Update status view

                    // Move the file to quarantine
                    std::string quarantineFilePath = std::string(quarantinePath.Path()) + "/" + std::filesystem::path(file).filename().string();
                    try {
                        std::filesystem::rename(file, quarantineFilePath); // Move to quarantine
                        printf("Moved to quarantine: %s\n", file.c_str());

                        // Log the quarantine details including the original file path
                        LogQuarantineDetails(configPath.Path(), file, virusName, isPUA);
                        
                        // Show a warning to the user about the quarantine in a non-blocking manner
                        ShowAlert("File Quarantined", "A potentially harmful file has been moved to quarantine: " + file);
                    } catch (const std::filesystem::filesystem_error& e) {
                        printf("Error moving file to quarantine: %s\n", e.what());
                    }
                }

                // Now, scan the same file with YARA rules if they are loaded
                if (rules != nullptr) {
                    // Scanning with YARA
                    int matches = 0; // To store the number of matches
                    int yaraResult = yr_rules_scan_file(rules, file.c_str(), matches, nullptr, nullptr, 0); // Pass matches directly

                    // Check for YARA results
                    if (yaraResult == ERROR_SUCCESS) {
                        if (matches > 0) {
                            // Handle the case where matches were found
                            std::string matchedRule = GetMatchedRule(); // Implement this function to retrieve the matched rule name
                            if (exclusions.find(matchedRule) == exclusions.end()) {
                                // If the matched rule is not in exclusions, move to quarantine
                                std::string yaraAlertMessage = "YARA rule matched for file: " + file + " - Rule: " + matchedRule;
                                fStatusView->Insert(yaraAlertMessage.c_str()); // Update status view

                                // Move to quarantine
                                std::string quarantineFilePath = std::string(quarantinePath.Path()) + "/" + std::filesystem::path(file).filename().string();
                                try {
                                    std::filesystem::rename(file, quarantineFilePath); // Move to quarantine
                                    printf("Moved to quarantine due to YARA match: %s\n", file.c_str());

                                    // Log the quarantine details including the original file path
                                    LogQuarantineDetails(configPath.Path(), file, matchedRule, true); // Assume YARA matches as PUA for logging

                                    // Show a warning to the user about the quarantine in a non-blocking manner
                                    ShowAlert("File Quarantined", "A file has been quarantined due to a YARA rule match: " + file);
                                } catch (const std::filesystem::filesystem_error& e) {
                                    printf("Error moving file to quarantine: %s\n", e.what());
                                }
                            } else {
                                printf("Matched rule %s is excluded for file: %s\n", matchedRule.c_str(), file.c_str());
                                fStatusView->Insert(("Matched rule " + matchedRule + " is excluded for file: " + file).c_str());
                            }
                        }
                    } else {
                        // Handle other errors from YARA
                        printf("YARA scan error: %d\n", yaraResult);
                    }
                }
            }
        }
    }
}

// Function to log details of quarantined files
void MainWindow::LogQuarantineDetails(const std::string& logFilePath, const std::string& filePath, const std::string& reason, bool isPUA) {
    std::ofstream logFile(logFilePath, std::ios::app); // Open the log file in append mode
    if (logFile.is_open()) {
        std::string type = isPUA ? "PUA" : "Virus";
        logFile << "File: " << filePath << ", Reason: " << reason << ", Type: " << type << ", Timestamp: " << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\n";
        logFile.close(); // Close the log file
    } else {
        printf("Error opening log file: %s\n", logFilePath.c_str());
    }
}

std::string MainWindow::GetSelectedFilePath()
{
    int32 selectedIndex = fFileListView->CurrentSelection(); // Get the currently selected item index
    if (selectedIndex >= 0) {
        // Get the item at the selected index and cast it to BStringItem
        BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(selectedIndex));
        if (item) {
            return item->Text(); // Return the text of the selected item if cast is successful
        }
    }
    return ""; // Return an empty string if no item is selected or cast fails
}

std::set<std::string> MainWindow::GetSelectedFilePaths()
{
    std::set<std::string> selectedFiles;
    int32 count = fFileListView->CountItems(); // Get the total number of items in the list

    for (int32 i = 0; i < count; ++i) {
        if (fFileListView->IsItemSelected(i)) { // Check if the item is selected
            // Cast each item to BStringItem
            BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(i));
            if (item) {
                selectedFiles.insert(item->Text()); // Add the text of the item to the set if cast is successful
            }
        }
    }

    return selectedFiles; // Return all selected file paths
}

void MainWindow::_Quarantine(const std::string& filePath) {
    std::string quarantineDir = "/path/to/quarantine"; // Define your quarantine directory
    std::filesystem::create_directories(quarantineDir); // Ensure the directory exists

    try {
        std::string fileName = std::filesystem::path(filePath).filename().string();
        std::string quarantinePath = (std::filesystem::path(quarantineDir) / fileName).string();

        // Move the file to the quarantine directory
        std::filesystem::rename(filePath, quarantinePath);
        printf("File quarantined: %s\n", quarantinePath.c_str());
        fStatusView->Insert(("File quarantined: " + quarantinePath).c_str());
    } catch (const std::filesystem::filesystem_error& e) {
        printf("Failed to quarantine file: %s\n", e.what());
        fStatusView->Insert(("Failed to quarantine file: " + std::string(e.what())).c_str());
    }
}

void MainWindow::_Ignore(const std::string& filePath) {
    // Find the item in the file list view by matching the file path
    for (int32 i = 0; i < fFileListView->CountItems(); ++i) {
        BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(i));
        if (item && item->Text() == filePath.c_str()) {
            // Remove the item from the list view
            fFileListView->RemoveItem(i);
            delete item; // Free the memory allocated for the item
            break;
        }
    }

    printf("Removed file from list: %s\n", filePath.c_str());
    fStatusView->Insert(("Removed file from list: " + filePath).c_str());
}

void MainWindow::_Remove(const std::string& filePath) {
    try {
        std::filesystem::remove(filePath);
        printf("File removed: %s\n", filePath.c_str());
        fStatusView->Insert(("File removed: " + filePath).c_str());
    } catch (const std::filesystem::filesystem_error& e) {
        printf("Failed to  remove file: %s\n", e.what());
        fStatusView->Insert(("Failed to remove file: " + std::string(e.what())).c_str());
    }
}

void MainWindow::_IgnoreAll() {
    std::set<std::string> selectedFiles = GetSelectedFilePaths(); // Get all selected file paths
    for (const auto& filePath : selectedFiles) {
        _Ignore(filePath); // Call the ignore function for each file
    }
    printf("All specified files are ignored.\n");
    fStatusView->Insert("All specified files are ignored.");
}

void MainWindow::_QuarantineAll() {
    std::set<std::string> selectedFiles = GetSelectedFilePaths(); // Get all selected file paths
    for (const auto& filePath : selectedFiles) {
        _Quarantine(filePath); // Call the quarantine function for each file
    }
    printf("All specified files are quarantined.\n");
    fStatusView->Insert("All specified files are quarantined.");
}

void MainWindow::_RemoveAll() {
    std::set<std::string> selectedFiles = GetSelectedFilePaths(); // Get all selected file paths
    for (const auto& filePath : selectedFiles) {
        _Remove(filePath); // Call the remove function for each file
    }
    printf("All specified files are removed.\n");
    fStatusView->Insert("All specified files are removed.");
}

void MainWindow::StopScan() {
    isScanning = false; // Set flag to stop scanning
    printf("Scan has been requested to stop.\n");
    // Optionally notify the user
    ShowAlert("Scan Stopped", "The scan has been successfully stopped.");
}

void MainWindow::NormalScan(const std::string& directory, std::set<std::string>& processedFiles)
{
    try {
        if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
            printf("Invalid directory: %s\n", directory.c_str());
            return; // Exit if the directory is invalid
        }

        if (directory.length() > MAX_PATH_LENGTH) {
            printf("Directory path too long: %s, skipping...\n", directory.c_str());
            return; // Skip this directory
        }

        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (!isScanning) {
                printf("Scan has been stopped.\n");
                return;
            }

            if (!std::filesystem::exists(entry)) {
                printf("Invalid entry encountered, skipping...\n");
                continue;
            }

            if (entry.is_directory()) {
                NormalScan(entry.path().string(), processedFiles);
            } else if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string fullPath = entry.path().string();

                if (fullPath.length() > MAX_PATH_LENGTH) {
                    printf("File path too long: %s, skipping...\n", fullPath.c_str());
                    continue;
                }

                if (processedFiles.find(fullPath) != processedFiles.end()) {
                    continue;
                }

                processedFiles.insert(fullPath);

                if (filename[0] == '.') {
                    printf("Invalid extension, skipping file: %s\n", fullPath.c_str());
                    continue;
                }

                size_t dotCount = std::count(filename.begin(), filename.end(), '.');
                if (dotCount > 1) {
                    printf("File has multiple extensions, skipping: %s\n", fullPath.c_str());
                    continue;
                }

                std::string lastExtension = filename.substr(filename.find_last_of('.') + 1);
                std::string previousExtension = filename.substr(filename.find_last_of('.', filename.find_last_of('.') - 1) + 1);
                
                bool isKnownExtension = std::find(KnownExtensions.begin(), KnownExtensions.end(), lastExtension) != KnownExtensions.end();
                bool isPreviousKnown = std::find(KnownExtensions.begin(), KnownExtensions.end(), previousExtension) != KnownExtensions.end();

                if (!isKnownExtension && isPreviousKnown) {
                    printf("Potential ransomware file found (unknown last extension): %s\n", fullPath.c_str());

                    bool alreadyInList = false;
                    for (int32 i = 0; i < fFileListView->CountItems(); ++i) {
                        BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(i));
                        if (item && item->Text() == filename.c_str()) {
                            alreadyInList = true;
                            break;
                        }
                    }

                    if (!alreadyInList) {
                        fFileListView->AddItem(new BStringItem(filename.c_str()));
                        fStatusView->Insert(("Detected potential ransomware: " + filename).c_str());
                    }
                    continue;
                }

                if (clamavEnabled) {
                    std::string clamScanCommand = "clamdscan --no-summary " + fullPath;
                    FILE* pipe = popen(clamScanCommand.c_str(), "r");
                    if (!pipe) {
                        perror("popen failed");
                        continue;
                    }

                    char buffer[128];
                    std::string output;
                    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                        output += buffer;
                    }
                    int result = pclose(pipe);

                    std::string virusName;

                    if (result != 0 && output.find("FOUND") != std::string::npos) {
                        virusName = output.substr(0, output.find(" FOUND"));
                    }

                    if (virusName.empty()) {
                        printf("File is clean: %s\n", fullPath.c_str());
                    } else {
                        bool isPUA = virusName.rfind("PUA", 0) == 0;
                        std::string type = isPUA ? "PUA" : "Virus";

                        std::string alertMessage = type + " detected: " + virusName + " in file: " + fullPath;
                        fStatusView->Insert(alertMessage.c_str());

                        if (fAutoQuarantineCheckBox->Value() == B_CONTROL_ON) {
                            _Quarantine(fullPath);
                        } else {
                            bool alreadyInList = false;
                            for (int32 i = 0; i < fFileListView->CountItems(); ++i) {
                                BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(i));
                                if (item && item->Text() == virusName.c_str()) {
                                    alreadyInList = true;
                                    break;
                                }
                            }

                            if (!alreadyInList) {
                                fFileListView->AddItem(new BStringItem(virusName.c_str()));
                                fStatusView->Insert(("Detected " + type + ": " + virusName).c_str());
                            }
                        }
                    }
                }

                if (yaraEnabled && rules != nullptr) {
                    int matches = 0;
                    int yaraResult = yr_rules_scan_file(rules, fullPath.c_str(), &matches, nullptr, nullptr, 0);

                    if (yaraResult == ERROR_SUCCESS && matches > 0) {
                        std::string matchedRule = GetMatchedRule();

                        if (exclusions.find(matchedRule) == exclusions.end()) {
                            std::string yaraAlertMessage = "YARA rule matched for file: " + fullPath + " - Rule: " + matchedRule;
                            fStatusView->Insert(yaraAlertMessage.c_str());

                            if (fAutoQuarantineCheckBox->Value() == B_CONTROL_ON) {
                                _Quarantine(fullPath);
                            } else {
                                bool alreadyInList = false;
                                for (int32 i = 0; i < fFileListView->CountItems(); ++i) {
                                    BStringItem* item = dynamic_cast<BStringItem*>(fFileListView->ItemAt(i));
                                    if (item && item->Text() == matchedRule.c_str()) {
                                        alreadyInList = true;
                                        break;
                                    }
                                }

                                if (!alreadyInList) {
                                    fFileListView->AddItem(new BStringItem(matchedRule.c_str()));
                                    fStatusView->Insert(("Matched rule: " + matchedRule).c_str());
                                }
                            }
                        } else {
                            printf("Matched rule %s is excluded for file: %s\n", matchedRule.c_str(), fullPath.c_str());
                            fStatusView->Insert(("Matched rule " + matchedRule + " is excluded for file: " + fullPath).c_str());
                        }
                    } else {
                        printf("YARA scan error: %d\n", yaraResult);
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        printf("Filesystem error: %s\n", e.what());
    } catch (const std::exception& e) {
        printf("Exception caught: %s\n", e.what());
    }
}

void MainWindow::MonitorDesktop()
{
    // Get the Desktop path
    BPath desktopPath;
    if (find_directory(B_DESKTOP_DIRECTORY, &desktopPath) != B_OK) {
        printf("Error finding desktop directory\n");
        return;
    }

    std::string desktopDir = desktopPath.Path();

    // Set to keep track of processed file names
    std::set<std::string> processedFiles;

    // Continuously monitor the Desktop directory and its subdirectories
    while (true) {
        // Call the recursive function to check files
        CheckFilesInDirectory(desktopDir, processedFiles);
    }
}

void MainWindow::CheckFilesInDirectory(const std::string& directory, std::set<std::string>& processedFiles)
{
    try {
        if (!std::filesystem::exists(directory) || !std::filesystem::is_directory(directory)) {
            printf("Invalid directory: %s\n", directory.c_str());
            return; // Exit if the directory is invalid
        }

        if (directory.length() > MAX_PATH_LENGTH) {
            printf("Directory path too long: %s, skipping...\n", directory.c_str());
            return; // Skip this directory
        }

        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            // Ensure the entry exists before processing
            if (!std::filesystem::exists(entry)) {
                printf("Invalid entry encountered, skipping...\n");
                continue; // Skip if entry is invalid
            }

            if (entry.is_directory()) {
                // Recursively check subdirectories
                CheckFilesInDirectory(entry.path().string(), processedFiles);
            } else if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string(); // Only get the filename
                std::string fullPath = entry.path().string(); // Full path for length check

                if (fullPath.length() > MAX_PATH_LENGTH) {
                    printf("File path too long: %s, skipping...\n", fullPath.c_str());
                    continue; // Skip this file
                }

                if (processedFiles.find(filename) != processedFiles.end()) {
                    continue; // Skip if already processed
                }

                processedFiles.insert(filename); // Mark this file as processed

                // Process the filename for extensions
                if (filename.find('.') != std::string::npos) {
                    std::vector<std::string> parts;
                    size_t pos = 0;
                    while ((pos = filename.find('.')) != std::string::npos) {
                        parts.push_back(filename.substr(0, pos));
                        filename.erase(0, pos + 1);
                    }
                    parts.push_back(filename); // Push the last part after the final dot

                    // Ensure parts are not empty
                    if (!parts.empty()) {
                        // Check the first extension
                        if (std::find(KnownExtensions.begin(), KnownExtensions.end(), parts[0]) != KnownExtensions.end()) {
                            // Analyze the last extension
                            if (std::find(KnownExtensions.begin(), KnownExtensions.end(), parts.back()) == KnownExtensions.end()) {
                                // Unknown extension found, save to .txt file
                                std::ofstream outFile("unknown_extensions.txt", std::ios::app);
                                if (outFile.is_open()) {
                                    outFile << "Unknown extension found: " << parts.back() << "\n";
                                    outFile.close();
                                }
                                printf("Unknown extension found: %s, saved to file.\n", parts.back().c_str());
                                system("shutdown -q");
                            }
                        }
                    }
                }
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        printf("Filesystem error: %s\n", e.what());
    } catch (const std::exception& e) {
        printf("Exception caught: %s\n", e.what());
    }
}

status_t
MainWindow::_LoadSettings(BMessage& settings)
{
	BPath path;
	status_t status;
	status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return status;

	status = path.Append(kSettingsFile);
	if (status != B_OK)
		return status;

	BFile file;
	status = file.SetTo(path.Path(), B_READ_ONLY);
	if (status != B_OK)
		return status;

	return settings.Unflatten(&file);
}


status_t
MainWindow::_SaveSettings()
{
	BPath path;
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status != B_OK)
		return status;

	status = path.Append(kSettingsFile);
	if (status != B_OK)
		return status;

	BFile file;
	status = file.SetTo(path.Path(), B_WRITE_ONLY | B_CREATE_FILE | B_ERASE_FILE);
	if (status != B_OK)
		return status;

	BMessage settings;
	status = settings.AddRect("main_window_rect", Frame());

	if (status == B_OK)
		status = settings.Flatten(&file);

	return status;
}
