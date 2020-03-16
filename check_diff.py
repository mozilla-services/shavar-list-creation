list_names = [
  "base-track-digest256",
  "baseeff-track-digest256",
  "basew3c-track-digest256",
  "content-track-digest256",
  "contenteff-track-digest256",
  "contentw3c-track-digest256",
  "ads-track-digest256",
  "analytics-track-digest256",
  "social-track-digest256",
  "social-tracking-protection-digest256",
  "social-tracking-protection-facebook-digest256",
  "social-tracking-protection-twitter-digest256",
  "social-tracking-protection-linkedin-digest256",
  "social-tracking-protection-youtube-digest256",
  "mozstd-trackwhite-digest256",
  "google-trackwhite-digest256",
  "moztestpub-trackwhite-digest256",
  "mozstd-track-digest256",
  "mozfull-track-digest256",
  "mozplugin-block-digest256",
  "mozplugin2-block-digest256",
  "block-flash-digest256",
  "except-flash-digest256",
  "allow-flashallow-digest256",
  "except-flashallow-digest256",
  "block-flashsubdoc-digest256",
  "except-flashsubdoc-digest256",
  "except-flashinfobar-digest256",
  "mozstdstaging-trackwhite-digest256",
  "mozstdstaging-track-digest256",
  "mozfullstaging-track-digest256",
  "fastblock1-track-digest256",
  "fastblock1-trackwhite-digest256",
  "fastblock2-track-digest256",
  "fastblock2-trackwhite-digest256",
  "fastblock3-track-digest256",
  "base-fingerprinting-track-digest256",
  "content-fingerprinting-track-digest256",
  "base-cryptomining-track-digest256",
  "content-cryptomining-track-digest256",
  "fanboyannoyance-ads-digest256",
  "fanboysocial-ads-digest256",
  "easylist-ads-digest256",
  "easyprivacy-ads-digest256",
  "adguard-ads-digest256"
]

shavar_diff = open('shavar-diff.txt', 'wb')
# shavar_diff_list = []
disconnect_diff = open('disconnect-diff.txt', 'wb')
# disconnect_diff_list = []
for list_name in list_names:
    shavar_diff_list = []
    disconnect_diff_list = []

    shavar_ext = ".txt"
    disconnect_ext = ".log"
    shavar_log = open(list_name + shavar_ext, "rb")
    disconnect_log = open(list_name + disconnect_ext, "rb")
    print('!!! Checking diff for {} !!!'.format(list_name))
    for line in shavar_log:
        disconnect_line = disconnect_log.readline()
        if line != disconnect_line:
            if '[m] ' in line:
                shavar_diff_list.append(line[4:])
                disconnect_diff_list.append(disconnect_line[4:])
            # shavar_diff.write(line)
            print('Shavar: {}'.format(line))
            # disconnect_diff.write(disconnect_line)
            print('Disconnect: {}'.format(disconnect_line))
    shavar_diff.write('!!! Checking diff for {} !!!\n'.format(list_name))
    if len(shavar_diff_list) != len(disconnect_diff_list):
        shavar_diff.write('Shavar: {}\n'.format(len(shavar_diff_list)))
        shavar_diff.write('Disconnect: {}\n'.format(len(disconnect_diff_list)))
    for diff in shavar_diff_list:
        if diff not in disconnect_diff_list:
            shavar_diff.write(diff)
    shavar_log.close()
    disconnect_log.close()
shavar_diff.close()
disconnect_diff.close()
