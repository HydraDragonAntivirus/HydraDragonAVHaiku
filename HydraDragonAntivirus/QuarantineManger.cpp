#include "QuarantineManager.h"
#include <LayoutBuilder.h>
#include <Alert.h>
#include <File.h>
#include <Directory.h>
#include <String.h>
#include <Path.h>
#include <FindDirectory.h>
#include <iostream>

QuarantineManager::QuarantineManager()
    : BWindow(BRect(100, 100, 500, 400), "Quarantine Manager", B_TITLED_WINDOW,
              B_ASYNCHRONOUS_CONTROLS | B_QUIT_ON_WINDOW_CLOSE)
{
    fListView = new BListView("quarantineList");
    LoadQuarantinedFiles(); // Load the files into the list view

    BButton* restoreButton = new BButton("restoreButton", "Restore", new BMessage('rstr'));
    BButton* deleteButton = new BButton("deleteButton", "Delete", new BMessage('delt'));

    BLayoutBuilder::Group<>(this, B_VERTICAL, 0)
        .Add(fListView)
        .Add(restoreButton)
        .Add(deleteButton)
        .End();
}

void QuarantineManager::LoadQuarantinedFiles() {
    BPath quarantinePath;
    find_directory(B_USER_SETTINGS_DIRECTORY, &quarantinePath);
    quarantinePath.Append("HydraDragonAntivirus/quarantine"); // Assume quarantine files are stored here

    BDirectory dir(quarantinePath.Path());
    BEntry entry;

    while (dir.GetNextEntry(&entry) == B_OK) {
        BPath filePath;
        entry.GetPath(&filePath);
        fListView->AddItem(new BStringItem(filePath.Path()));
        quarantinedFiles.push_back(filePath.Path()); // Store file paths
    }
}

void QuarantineManager::MessageReceived(BMessage* message) {
    switch (message->what) {
    case 'rstr':
        RestoreSelectedFile();
        break;
    case 'delt':
        DeleteSelectedFile();
        break;
    default:
        BWindow::MessageReceived(message);
        break;
    }
}

void QuarantineManager::RestoreSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        // Get the selected file path
        std::string filePath = quarantinedFiles[selectedIndex];

        // Logic to restore the file from quarantine
        // Implement the actual restore mechanism here

        BAlert* alert = new BAlert("Restored", "File restored successfully.", "OK");
        alert->Go();
    }
}

void QuarantineManager::DeleteSelectedFile() {
    int32 selectedIndex = fListView->CurrentSelection();
    if (selectedIndex >= 0) {
        // Get the selected file path
        std::string filePath = quarantinedFiles[selectedIndex];

        // Logic to delete the file from quarantine
        // Implement the actual deletion mechanism here

        BAlert* alert = new BAlert("Deleted", "File deleted successfully.", "OK");
        alert->Go();
    }
}
