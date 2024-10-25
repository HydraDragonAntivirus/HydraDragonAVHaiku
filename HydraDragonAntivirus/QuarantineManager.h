#ifndef QUARANTINEMANAGER_H
#define QUARANTINEMANAGER_H

#include <Window.h>
#include <View.h>
#include <TextView.h>
#include <ListView.h>
#include <Button.h>
#include <FilePanel.h>
#include <string>
#include <vector>

class QuarantineManager : public BWindow {
public:
    QuarantineManager();
    virtual void MessageReceived(BMessage* message) override;

private:
    void LoadQuarantinedFiles();
    void RestoreSelectedFile();
    void DeleteSelectedFile();
    void RestoreAllFiles();  // New method for restoring all files
    void DeleteAllFiles();   // New method for deleting all files

    BListView* fListView;
    BButton* restoreButton;      // Button to restore selected file
    BButton* deleteButton;       // Button to delete selected file
    BButton* restoreAllButton;   // New button to restore all files
    BButton* deleteAllButton;    // New button to delete all files

    std::vector<std::string> quarantinedFiles; // Vector to store file paths
};

#endif // QUARANTINEMANAGER_H
