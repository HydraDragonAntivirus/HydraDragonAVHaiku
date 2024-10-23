#include "MainWindow.h"
#include "knownExtensions.h"

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
#include <iostream>
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

#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "Window"
#define MAX_PATH_LENGTH 255

static const uint32 kMsgStartMonitor = 'strt';
static const uint32 kMsgQuitApp = 'quit';
static const uint32 kMsgInstallClamAV = 'inst';
static const uint32 kMsgChangeMonitorDirectory = 'chmd';

static const char* kSettingsFile = "Hydra Dragon Antivirus Settings";

// List of known file extensions
std::vector<std::string> knownExtensions = getKnownExtensions();

MainWindow::MainWindow() 
    : BWindow(BRect(100, 100, 500, 400), B_TRANSLATE("Hydra Dragon Antivirus"), B_TITLED_WINDOW,
              B_ASYNCHRONOUS_CONTROLS | B_QUIT_ON_WINDOW_CLOSE)
{
    CreateConfigDirectory(); // Create the config directory

    BMenuBar* menuBar = _BuildMenu();

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(menuBar)
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
}

BMenuBar* MainWindow::_BuildMenu()
{
    BMenuBar* menuBar = new BMenuBar("menubar");
    BMenu* menu;
    BMenuItem* item;

    // 'Monitor' Menu
    menu = new BMenu(B_TRANSLATE("Monitor"));

    item = new BMenuItem(B_TRANSLATE("Start Monitoring"), new BMessage(kMsgStartMonitor), 'S');
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Change Monitor Directory"), new BMessage(kMsgChangeMonitorDirectory));
    menu->AddItem(item);

    item = new BMenuItem(B_TRANSLATE("Quit"), new BMessage(kMsgQuitApp), 'Q');
    menu->AddItem(item);

    menuBar->AddItem(menu);

    // 'Installation' Menu
    menu = new BMenu(B_TRANSLATE("Installation")); // New menu for installations
    item = new BMenuItem(B_TRANSLATE("Install ClamAV"), new BMessage(kMsgInstallClamAV));
    menu->AddItem(item);

    menuBar->AddItem(menu);

    // 'Help' Menu
    menu = new BMenu(B_TRANSLATE("Help"));
    item = new BMenuItem(B_TRANSLATE("About" B_UTF8_ELLIPSIS), new BMessage(B_ABOUT_REQUESTED));
    item->SetTarget(be_app);
    menu->AddItem(item);

    menuBar->AddItem(menu);

    return menuBar;
}

void MainWindow::MessageReceived(BMessage* message)
{
    switch (message->what) {
    case kMsgStartMonitor:
        StartMonitoring();
        break;

    case kMsgQuitApp:
        PostMessage(B_QUIT_REQUESTED);
        break;

    case kMsgInstallClamAV: // Handle ClamAV installation
        InstallClamAV();
        break;

    case kMsgChangeMonitorDirectory: // Handle directory change
        ChangeMonitorDirectory();
        break;

    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void CreateConfigDirectory() {
    BPath configPath;
    status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &configPath);
    if (status != B_OK) {
        std::cerr << "Error finding user settings directory" << std::endl;
        return;
    }

    // Append HydraDragonAntivirus directory name
    configPath.Append("HydraDragonAntivirus");

    BDirectory configDir(configPath.Path());
    if (configDir.InitCheck() != B_OK) {
        // Create the directory if it doesn't exist
        if (mkdir(configPath.Path(), 0755) != 0) {
            std::cerr << "Error creating config directory" << std::endl;
        } else {
            std::cout << "Config directory created: " << configPath.Path() << std::endl;
        }
    } else {
        std::cout << "Config directory already exists: " << configPath.Path() << std::endl;
    }
}

void UpdateConfigFile(const std::string& selectedDirectory) {
    BPath configPath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &configPath);
    configPath.Append("HydraDragonAntivirus");
    configPath.Append("config.txt"); // or any specific config file name

    BFile configFile(configPath.Path(), B_WRITE_ONLY | B_CREATE_FILE);
    if (configFile.InitCheck() != B_OK) {
        std::cerr << "Error opening config file for writing" << std::endl;
        return;
    }

    // Write the selected directory to the config file
    configFile.Write(selectedDirectory.c_str(), selectedDirectory.size());
    std::cout << "Configuration file updated with directory: " << selectedDirectory << std::endl;
}

void MainWindow::ChangeMonitorDirectory()
{
    BFilePanel* filePanel = new BFilePanel(B_OPEN_PANEL, 
        new BMessenger(this), 
        nullptr, 
        B_DIRECTORY_NODE, 
        false);

    filePanel->Show();
}

void MainWindow::RefsReceived(BMessage* message)
{
    entry_ref ref;
    while (message->FindRef("refs", &ref) == B_OK) {
        BPath path(&ref);
        if (path.InitCheck() == B_OK) {
            monitoringDirectory = path.Path(); // Update the monitoring directory
            printf("Monitoring directory changed to: %s\n", monitoringDirectory.String());

            // Call UpdateConfigFile to update the configuration file
            UpdateConfigFile(monitoringDirectory.String());
        }
    }
}

void MainWindow::InstallClamAV() {
    printf("Installing ClamAV...\n");

    // Install ClamAV without confirmation
    system("pkgman install -y clamav"); 

    // Copy clamavconfig/freshclam.conf to /boot/system/settings/clamav/
    system("cp -f clamavconfig/freshclam.conf /boot/system/settings/clamav/");

    // Copy the db folder to the ClamAV settings directory
    system("cp -rf db /boot/system/settings/clamav/db");

    // Run freshclam to update the virus definitions
    system("freshclam");

    // Show a message box at the end of the process
    BAlert* alert = new BAlert("ClamAV Installation", 
                               "ClamAV installation and setup completed successfully.", 
                               "OK");
    alert->Go();  // Display the message box
}

void MainWindow::StartMonitoring()
{
    printf("Monitoring started\n");
    std::thread monitoringThread(&MainWindow::MonitorDesktop, this);
    monitoringThread.detach(); // Detach the thread to run independently
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
                        if (std::find(knownExtensions.begin(), knownExtensions.end(), parts[0]) != knownExtensions.end()) {
                            // Analyze the last extension
                            if (std::find(knownExtensions.begin(), knownExtensions.end(), parts.back()) == knownExtensions.end()) {
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

status_t MainWindow::_LoadSettings(BMessage& settings)
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

status_t MainWindow::_SaveSettings()
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
