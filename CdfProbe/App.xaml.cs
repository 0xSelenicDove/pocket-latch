using Windows.ApplicationModel.Activation;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace CdfProbe
{
    sealed partial class App : Application
    {
        public App() { InitializeComponent(); }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            if (!(Window.Current.Content is Frame))
            {
                var frame = new Frame();
                Window.Current.Content = frame;
                try { frame.Navigate(typeof(MainPage)); }
                catch (System.Exception error)
                {
                    CdfProbe.Shared.ProbeState.Error("Open window", error);
                    frame.Content = new TextBlock {
                        Text = "PocketLatch could not open.\n\n" + error,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(24),
                        IsTextSelectionEnabled = true
                    };
                }
            }
            Window.Current.Activate();
        }
    }
}
